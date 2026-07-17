package peerstore

import (
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"
)

type WrappedConnection interface {
	ID() string
	RemoteAddr() net.Addr
	Close()
	Run()
	GrpcClient() *grpc.ClientConn
	SendDatagram([]byte) error
}

type PeerInfo struct {
	Id         string            `json:"id"`
	LastSeen   time.Time         `json:"last_seen"`
	Address    string            `json:"address"`
	Connection WrappedConnection `json:"_"`
}

func (pi *PeerInfo) Connected() bool {
	return pi.Connection != nil
}

type PeerStore struct {
	store    map[string]*PeerInfo
	storeMut sync.RWMutex
}

func NewPeerStore() *PeerStore {
	return &PeerStore{
		store: map[string]*PeerInfo{},
	}
}

func (ps *PeerStore) SendDatagram(peerID string, data []byte) error {
	ps.storeMut.RLock()
	defer ps.storeMut.RUnlock()

	v, ex := ps.Get(peerID)
	if !ex {
		return fmt.Errorf("peer not found")
	}
	return v.Connection.SendDatagram(data)
}

func (ps *PeerStore) List() []*PeerInfo {
	r := make([]*PeerInfo, 0)
	ps.storeMut.RLock()
	for _, pi := range ps.store {
		r = append(r, pi)
	}
	ps.storeMut.RUnlock()

	return r
}
func (ps *PeerStore) ListConnected() []*PeerInfo {
	r := make([]*PeerInfo, 0)
	ps.storeMut.RLock()
	for _, pi := range ps.store {
		if pi.Connected() {
			r = append(r, pi)
		}
	}
	ps.storeMut.RUnlock()
	return r
}

func (ps *PeerStore) Count() int {
	ps.storeMut.RLock()
	defer ps.storeMut.RUnlock()
	return len(ps.store)
}
func (ps *PeerStore) Exists(key string) bool {
	ps.storeMut.RLock()
	defer ps.storeMut.RUnlock()
	_, ex := ps.store[key]
	return ex
}
func (ps *PeerStore) Get(key string) (*PeerInfo, bool) {
	ps.storeMut.RLock()
	defer ps.storeMut.RUnlock()
	val, ex := ps.store[key]
	return val, ex
}
func (ps *PeerStore) Set(info *PeerInfo) {
	ps.storeMut.Lock()
	defer ps.storeMut.Unlock()

	ps.store[info.Id] = info
}
func (ps *PeerStore) InsertMerge(update *PeerInfo) {
	pi, ex := ps.Get(update.Id)
	if !ex {
		ps.Set(update)
		return
	}

	if update.LastSeen.After(pi.LastSeen) {
		pi.LastSeen = update.LastSeen
	}

	if update.LastSeen.After(pi.LastSeen) || (pi.Address == "" && update.Address != "") {
		pi.LastSeen = update.LastSeen
	}

	if update.Connection != nil {
		pi.Connection = update.Connection
	}

}
func (ps *PeerStore) Save(filename string) error {
	ps.storeMut.RLock()
	raw := maps.Clone(ps.store)
	ps.storeMut.RUnlock()
	data, err := json.Marshal(raw)
	if err != nil {
		return fmt.Errorf("marshal error: %w", err)
	}

	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		return fmt.Errorf("write file error: %w", err)
	}
	return nil
}
func (ps *PeerStore) Load(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	var temp map[string]*PeerInfo
	err = json.Unmarshal(data, &temp)
	if err != nil {
		return fmt.Errorf("unmarshal error: %w", err)
	}

	ps.storeMut.Lock()
	ps.store = temp
	ps.storeMut.Unlock()
	return nil
}

func (ps *PeerStore) SetDisconnected(key string) {
	ps.storeMut.Lock()
	defer ps.storeMut.Unlock()
	val, ex := ps.store[key]
	if ex {
		val.Connection = nil
	}
}

func (ps *PeerStore) Connected(key string) bool {
	ps.storeMut.RLock()
	defer ps.storeMut.RUnlock()
	val, ex := ps.store[key]
	if !ex {
		return false
	}
	return val.Connected()
}
