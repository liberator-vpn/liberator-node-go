package router

import (
	"context"
)

const (
	EventType_ClientConnected    RouterEventType = 1
	EventType_ClientDisconnected RouterEventType = 2
)

type RouterEventType int
type RouterEvent struct {
	Type      RouterEventType
	VirtualIP uint32
	NodeID    string
}

// Routing table events
func (s *Router) SubscribeEvents(ctx context.Context) (<-chan RouterEvent, context.CancelFunc) {
	ch := make(chan RouterEvent, 200)

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

func (s *Router) notify(event RouterEvent) {
	s.subsMut.Lock()
	defer s.subsMut.Unlock()

	for ch := range s.subs {
		select {
		case ch <- event:
		default:
		}
	}
}
