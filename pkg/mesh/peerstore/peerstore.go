package peerstore

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"sync"
	"time"

	"github.com/TexHik620953/liberator-node-go/pkg/mesh/discovery/proto"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/transport"
)

type PeerInfo struct {
	Id         string                      `json:"id"`
	LastSeen   time.Time                   `json:"last_seen"`
	Address    string                      `json:"address"`
	Connection transport.WrappedConnection `json:"-"`
}

func (pi *PeerInfo) Connected() bool {
	return pi.Connection != nil
}

func (pi *PeerInfo) clone() *PeerInfo {
	if pi == nil {
		return nil
	}
	return &PeerInfo{
		Id:         pi.Id,
		LastSeen:   pi.LastSeen,
		Address:    pi.Address,
		Connection: pi.Connection,
	}
}

type PeerStore struct {
	store    map[string]*PeerInfo
	storeMut sync.RWMutex
	subs     map[chan *proto.PeerEvent]struct{}
}

func NewPeerStore() *PeerStore {
	return &PeerStore{
		store: map[string]*PeerInfo{},
		subs:  make(map[chan *proto.PeerEvent]struct{}),
	}
}

func (ps *PeerStore) Get(id string) (*PeerInfo, bool) {
	ps.storeMut.RLock()
	defer ps.storeMut.RUnlock()
	val, ok := ps.store[id]
	if !ok {
		return nil, false
	}
	return val.clone(), true
}

func (ps *PeerStore) List() []*PeerInfo {
	ps.storeMut.RLock()
	defer ps.storeMut.RUnlock()
	res := make([]*PeerInfo, 0, len(ps.store))
	for _, p := range ps.store {
		res = append(res, p.clone())
	}
	return res
}

func (ps *PeerStore) ListConnected() []*PeerInfo {
	ps.storeMut.RLock()
	defer ps.storeMut.RUnlock()
	res := make([]*PeerInfo, 0)
	for _, p := range ps.store {
		if p.Connected() {
			res = append(res, p.clone())
		}
	}
	return res
}

func (ps *PeerStore) Count() int {
	ps.storeMut.RLock()
	defer ps.storeMut.RUnlock()
	return len(ps.store)
}

func (ps *PeerStore) InsertMerge(update *PeerInfo) {
	ps.storeMut.Lock()
	defer ps.storeMut.Unlock()

	existing, ok := ps.store[update.Id]
	if !ok {
		ps.store[update.Id] = update.clone()
		ps.notifyLocked(&proto.PeerEvent{
			Type: proto.PeerEventType_PEER_EVENT_JOINED,
			Update: &proto.PeerInfo{
				Id:       update.Id,
				Addr:     update.Address,
				LastSeen: update.LastSeen.UnixNano(),
			},
		})
		return
	}

	changed := false
	if update.LastSeen.After(existing.LastSeen) {
		existing.LastSeen = update.LastSeen
		changed = true
	}
	if update.Address != "" && update.Address != existing.Address {
		existing.Address = update.Address
		changed = true
	}
	if update.Connection != nil && update.Connection != existing.Connection {
		if existing.Connection != nil {
			existing.Connection.Close()
		}
		existing.Connection = update.Connection
		changed = true
	}
	if !changed {
		return
	}
	ps.notifyLocked(&proto.PeerEvent{
		Type: proto.PeerEventType_PEER_EVENT_UPDATED,
		Update: &proto.PeerInfo{
			Id:       existing.Id,
			Addr:     existing.Address,
			LastSeen: existing.LastSeen.UnixNano(),
		},
	})
}

func (ps *PeerStore) SetDisconnected(id string) {
	ps.storeMut.Lock()
	defer ps.storeMut.Unlock()
	pi, ok := ps.store[id]
	if !ok {
		return
	}
	if pi.Connection == nil {
		return
	}
	pi.Connection.Close()
	pi.Connection = nil
	ps.notifyLocked(&proto.PeerEvent{
		Type: proto.PeerEventType_PEER_EVENT_LEFT,
		Update: &proto.PeerInfo{
			Id:       pi.Id,
			Addr:     pi.Address,
			LastSeen: pi.LastSeen.UnixNano(),
		},
	})
}

func (ps *PeerStore) Remove(id string) {
	ps.storeMut.Lock()
	defer ps.storeMut.Unlock()
	pi, ok := ps.store[id]
	if !ok {
		return
	}
	if pi.Connection != nil {
		pi.Connection.Close()
	}
	delete(ps.store, id)
	ps.notifyLocked(&proto.PeerEvent{
		Type: proto.PeerEventType_PEER_EVENT_LEFT,
		Update: &proto.PeerInfo{
			Id:       pi.Id,
			Addr:     pi.Address,
			LastSeen: pi.LastSeen.UnixNano(),
		},
	})
}

func (ps *PeerStore) Subscribe(ctx context.Context) (<-chan *proto.PeerEvent, func()) {
	ps.storeMut.Lock()
	defer ps.storeMut.Unlock()
	ch := make(chan *proto.PeerEvent, 100)
	ps.subs[ch] = struct{}{}
	unsub := func() {
		ps.storeMut.Lock()
		defer ps.storeMut.Unlock()
		if _, ok := ps.subs[ch]; ok {
			delete(ps.subs, ch)
			close(ch)
		}
	}
	return ch, unsub
}

func (ps *PeerStore) notifyLocked(ev *proto.PeerEvent) {
	for ch := range ps.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

func (ps *PeerStore) Save(filename string) error {
	ps.storeMut.RLock()
	copyMap := maps.Clone(ps.store)
	ps.storeMut.RUnlock()
	data, err := json.Marshal(copyMap)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return os.WriteFile(filename, data, 0644)
}

func (ps *PeerStore) Load(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}
	var temp map[string]*PeerInfo
	if err := json.Unmarshal(data, &temp); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	ps.storeMut.Lock()
	ps.store = temp
	ps.storeMut.Unlock()
	return nil
}
