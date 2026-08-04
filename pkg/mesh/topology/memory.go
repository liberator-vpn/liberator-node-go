package topology

import (
	"context"
	"sync"

	"github.com/TexHik620953/liberator-node-go/pkg/mesh/discovery/proto"
)

type inMemoryState struct {
	mu    sync.RWMutex
	peers map[string]*PeerInfo

	subsMut sync.Mutex
	subs    map[chan *proto.PeerEvent]struct{}
}

func newInMemoryState() *inMemoryState {
	return &inMemoryState{
		peers: make(map[string]*PeerInfo),
		subs:  make(map[chan *proto.PeerEvent]struct{}),
	}
}

func (s *inMemoryState) Get(id string) (PeerInfo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	p, ok := s.peers[id]
	if !ok {
		return PeerInfo{}, false
	}
	return *p.Clone(), true
}

func (s *inMemoryState) List() []PeerInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	list := make([]PeerInfo, 0, len(s.peers))
	for _, p := range s.peers {
		list = append(list, *p.Clone())
	}
	return list
}

func (s *inMemoryState) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.peers)
}

func (s *inMemoryState) InsertMerge(update PeerInfo) bool {
	if update.ID == "" {
		return false
	}

	s.mu.Lock()
	existing, ok := s.peers[update.ID]
	if !ok {
		existing = update.Clone()
		s.peers[update.ID] = existing
	} else {
		changed := false
		if update.LastSeen.After(existing.LastSeen) {
			existing.LastSeen = update.LastSeen
			changed = true
		}
		if update.Address != "" && update.Address != existing.Address {
			existing.Address = update.Address
			changed = true
		}
		if !changed {
			s.mu.Unlock()
			return false
		}
	}

	dropped, lost := s.resolveAddressConflict(existing)
	if lost {
		delete(s.peers, existing.ID)
	}
	event := &proto.PeerEvent{
		Type:   proto.PeerEventType_PEER_EVENT_UPDATED,
		Update: peerInfoToProto(existing),
	}
	switch {
	case lost && !ok:
		s.mu.Unlock()
		return false // мусор из gossip, даже не заводим запись
	case lost:
		event.Type = proto.PeerEventType_PEER_EVENT_LEFT
	case !ok:
		event.Type = proto.PeerEventType_PEER_EVENT_JOINED
	}
	s.mu.Unlock()

	s.notify(event)
	for _, p := range dropped {
		s.notify(&proto.PeerEvent{
			Type:   proto.PeerEventType_PEER_EVENT_LEFT,
			Update: peerInfoToProto(p),
		})
	}
	return true
}

// resolveAddressConflict: один адрес — одна нода, выживает запись со свежайшим LastSeen.
// Так протухшие ID (нода перевыпустила сертификат) не живут вечно и не расползаются
// по сети gossip'ом. Вызывается под s.mu.
func (s *inMemoryState) resolveAddressConflict(keep *PeerInfo) (dropped []*PeerInfo, keepLost bool) {
	if keep.Address == "" {
		return nil, false
	}

	for id, p := range s.peers {
		if id == keep.ID || p.Address != keep.Address {
			continue
		}
		if p.LastSeen.After(keep.LastSeen) {
			keepLost = true
		}
		if keep.LastSeen.After(p.LastSeen) {
			dropped = append(dropped, p)
		}
	}
	if keepLost {
		// Проигравший ничего не чистит: победитель по адресу сделает это на своей вставке.
		return nil, true
	}
	for _, p := range dropped {
		delete(s.peers, p.ID)
	}
	return dropped, false
}

func peerInfoToProto(p *PeerInfo) *proto.PeerInfo {
	return &proto.PeerInfo{
		Id:       p.ID,
		Addr:     p.Address,
		LastSeen: p.LastSeen.UnixNano(),
	}
}

func (s *inMemoryState) Remove(id string) {
	if id == "" {
		return
	}

	s.mu.Lock()
	existing, ok := s.peers[id]
	if !ok {
		s.mu.Unlock()
		return
	}

	delete(s.peers, id)
	s.mu.Unlock()

	s.notify(&proto.PeerEvent{
		Type:   proto.PeerEventType_PEER_EVENT_LEFT,
		Update: peerInfoToProto(existing),
	})
}

func (s *inMemoryState) Subscribe(ctx context.Context) (<-chan *proto.PeerEvent, context.CancelFunc) {
	ch := make(chan *proto.PeerEvent, 200)

	s.subsMut.Lock()
	s.subs[ch] = struct{}{}
	s.subsMut.Unlock()

	cancel := func() {
		s.subsMut.Lock()
		if _, ok := s.subs[ch]; ok {
			delete(s.subs, ch)
			close(ch)
		}
		s.subsMut.Unlock()
	}

	go func() {
		<-ctx.Done()
		cancel()
	}()

	return ch, cancel
}

func (s *inMemoryState) notify(event *proto.PeerEvent) {
	s.subsMut.Lock()
	defer s.subsMut.Unlock()

	for ch := range s.subs {
		select {
		case ch <- event:
		default:
		}
	}
}
