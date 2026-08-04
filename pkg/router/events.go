package router

import (
	"context"
)

type RouterEventType int

const (
	RouterEventType_ClientAdded   RouterEventType = 1
	RouterEventType_ClientRemoved RouterEventType = 2
)

type RouterEvent struct {
	Type      RouterEventType
	VirtualIP uint32
	NodeID    string
}

// Routing table events
func (s *Router) SubscribeRoutingEvents(ctx context.Context) (<-chan RouterEvent, context.CancelFunc) {
	ch := make(chan RouterEvent, 200)

	s.routingSubsMu.Lock()
	s.routingsubs[ch] = struct{}{}
	s.routingSubsMu.Unlock()

	cancel := func() {
		s.routingSubsMu.Lock()
		if _, ok := s.routingsubs[ch]; ok {
			delete(s.routingsubs, ch)
			close(ch)
		}
		s.routingSubsMu.Unlock()
	}

	go func() {
		<-ctx.Done()
		cancel()
	}()

	return ch, cancel
}

func (s *Router) notifyRoutingEvent(event RouterEvent) {
	s.routingSubsMu.Lock()
	defer s.routingSubsMu.Unlock()

	for ch := range s.routingsubs {
		select {
		case ch <- event:
		default:
		}
	}
}

type FirewallEventType int

const (
	FirewallEventType_RuleAdded   FirewallEventType = 1
	FirewallEventType_RuleRemoved FirewallEventType = 2
)

type FirewallEvent struct {
	Type FirewallEventType

	NodeID string
	RuleID uint64

	Address        uint32
	TargetAddress  *uint32
	Protocol       string
	PortRangeStart uint16
	PortRangeEnd   *uint16
}

func (s *Router) SubscribeFirewallEvents(ctx context.Context) (<-chan FirewallEvent, context.CancelFunc) {
	ch := make(chan FirewallEvent, 200)

	s.firewallSubsMu.Lock()
	s.firewallsubs[ch] = struct{}{}
	s.firewallSubsMu.Unlock()

	cancel := func() {
		s.firewallSubsMu.Lock()
		if _, ok := s.firewallsubs[ch]; ok {
			delete(s.firewallsubs, ch)
			close(ch)
		}
		s.firewallSubsMu.Unlock()
	}

	go func() {
		<-ctx.Done()
		cancel()
	}()

	return ch, cancel
}

func (s *Router) notifyFirewallEvent(event FirewallEvent) {
	s.firewallSubsMu.Lock()
	defer s.firewallSubsMu.Unlock()

	for ch := range s.firewallsubs {
		select {
		case ch <- event:
		default:
		}
	}
}
