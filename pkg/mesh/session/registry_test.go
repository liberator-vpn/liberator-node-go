package session

import (
	"context"
	"net"
	"testing"

	"github.com/TexHik620953/liberator-node-go/pkg/mesh/transport"
)

type fakeAddr string

func (a fakeAddr) Network() string { return "test" }
func (a fakeAddr) String() string  { return string(a) }

type fakeConn struct {
	id          string
	isInitiator bool
	ctx         context.Context
	cancel      context.CancelFunc
}

func newFakeConn(id string, isInitiator bool) *fakeConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &fakeConn{id: id, isInitiator: isInitiator, ctx: ctx, cancel: cancel}
}

func (c *fakeConn) ID() string                                     { return c.id }
func (c *fakeConn) RemoteAddr() net.Addr                           { return fakeAddr(c.id) }
func (c *fakeConn) OpenStream(context.Context) (net.Conn, error)   { return nil, nil }
func (c *fakeConn) AcceptStream(context.Context) (net.Conn, error) { return nil, nil }
func (c *fakeConn) SendDatagram([]byte) error                      { return nil }
func (c *fakeConn) RecvDatagram(context.Context) ([]byte, error)   { return nil, nil }
func (c *fakeConn) IsInitiator() bool                              { return c.isInitiator }
func (c *fakeConn) Close() error                                   { c.cancel(); return nil }
func (c *fakeConn) Context() context.Context                       { return c.ctx }
func (c *fakeConn) TotalSent() uint64                              { return 0 }
func (c *fakeConn) TotalRecv() uint64                              { return 0 }

var _ transport.PeerConnection = (*fakeConn)(nil)

func session(peerID string, conn *fakeConn) *Session {
	return &Session{PeerID: peerID, Conn: conn}
}

const (
	highID = "bbbb"
	lowID  = "aaaa"
)

// Лишний повторный dial/accept не должен рвать живую сессию — это и есть причина флапа.
func TestAddRejectsSameDirectionDuplicate(t *testing.T) {
	for _, tc := range []struct {
		name      string
		localID   string
		peerID    string
		initiator bool
	}{
		{"outbound on higher id", highID, lowID, true},
		{"inbound on lower id", lowID, highID, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRegistry(tc.localID)
			live := session(tc.peerID, newFakeConn("live", tc.initiator))
			if err := r.Add(live); err != nil {
				t.Fatalf("first add: %v", err)
			}
			if err := r.Add(session(tc.peerID, newFakeConn("dup", tc.initiator))); err == nil {
				t.Fatal("duplicate of the same direction must be rejected")
			}
			if got, _ := r.Get(tc.peerID); got != live {
				t.Fatal("live session must survive the duplicate")
			}
			if live.Conn.Context().Err() != nil {
				t.Fatal("live connection must not be closed")
			}
		})
	}
}

// Одновременный dial с двух сторон: обе ноды должны сойтись на одном коннекте —
// том, где инициатор это нода со старшим ID, независимо от порядка регистрации.
func TestAddResolvesSimultaneousDialSymmetrically(t *testing.T) {
	// x инициировала нода со старшим ID, y — с младшим.
	for _, first := range []string{"x", "y"} {
		t.Run("first="+first, func(t *testing.T) {
			high := NewRegistry(highID) // видит x как исходящее, y как входящее
			low := NewRegistry(lowID)   // наоборот

			add := func(r Registry, peerID string, connID string, initiator bool) {
				_ = r.Add(session(peerID, newFakeConn(connID, initiator)))
			}
			order := []string{first, map[string]string{"x": "y", "y": "x"}[first]}
			for _, c := range order {
				add(high, lowID, c, c == "x")
				add(low, highID, c, c == "y")
			}

			for name, r := range map[string]Registry{"high": high, "low": low} {
				peer := lowID
				if name == "low" {
					peer = highID
				}
				s, ok := r.Get(peer)
				if !ok || s.Conn.ID() != "x" {
					t.Fatalf("%s node kept %v, want x", name, s.Conn.ID())
				}
			}
		})
	}
}

// Мёртвая сессия (пир перезапустился) заменяется без ожидания idle timeout.
func TestAddReplacesDeadSession(t *testing.T) {
	r := NewRegistry(lowID)
	dead := session(highID, newFakeConn("dead", true))
	if err := r.Add(dead); err != nil {
		t.Fatalf("first add: %v", err)
	}
	_ = dead.Conn.Close()

	fresh := session(highID, newFakeConn("fresh", true))
	if err := r.Add(fresh); err != nil {
		t.Fatalf("dead session must be replaceable: %v", err)
	}
	if got, _ := r.Get(highID); got != fresh {
		t.Fatal("fresh session must win over the dead one")
	}
}

func TestAddRejectsSelf(t *testing.T) {
	r := NewRegistry(highID)
	if err := r.Add(session(highID, newFakeConn("self", true))); err == nil {
		t.Fatal("self connection must be rejected")
	}
}
