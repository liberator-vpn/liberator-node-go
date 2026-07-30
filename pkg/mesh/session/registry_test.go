package session

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	"github.com/TexHik620953/liberator-node-go/pkg/mesh/transport"
)

type registryTestConnection struct {
	initiator bool
	closed    atomic.Int32
}

func (c *registryTestConnection) SendDatagram([]byte) error {
	return nil
}

func (c *registryTestConnection) RecvDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (c *registryTestConnection) OpenStream(ctx context.Context) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (c *registryTestConnection) AcceptStream(ctx context.Context) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (c *registryTestConnection) ID() string {
	return "peer"
}

func (c *registryTestConnection) Context() context.Context {
	return context.Background()
}

func (c *registryTestConnection) RemoteAddr() net.Addr {
	return testAddr("peer")
}

func (c *registryTestConnection) Close() error {
	c.closed.Add(1)
	return nil
}

func (c *registryTestConnection) IsInitiator() bool {
	return c.initiator
}

type testAddr string

func (a testAddr) Network() string {
	return "test"
}

func (a testAddr) String() string {
	return string(a)
}

var _ transport.PeerConnection = (*registryTestConnection)(nil)

func TestSubscribeNewSessionsReplaysActiveSessions(t *testing.T) {
	registry := NewRegistry("local")
	session := &Session{
		PeerID: "peer",
		Conn:   &registryTestConnection{},
	}
	if err := registry.Add(session); err != nil {
		t.Fatalf("add session: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	select {
	case got := <-registry.SubscribeNewSessions(ctx):
		if got != session {
			t.Fatalf("unexpected session: got %p, want %p", got, session)
		}
	default:
		t.Fatal("active session was not replayed")
	}
}

func TestRemovingReplacedSessionKeepsCurrentSession(t *testing.T) {
	registry := NewRegistry("z-local")
	oldConn := &registryTestConnection{}
	oldSession := &Session{PeerID: "a-peer", Conn: oldConn}
	if err := registry.Add(oldSession); err != nil {
		t.Fatalf("add old session: %v", err)
	}

	newConn := &registryTestConnection{initiator: true}
	newSession := &Session{PeerID: "a-peer", Conn: newConn}
	if err := registry.Add(newSession); err != nil {
		t.Fatalf("replace session: %v", err)
	}
	if oldConn.closed.Load() != 1 {
		t.Fatalf("old connection close count: got %d, want 1", oldConn.closed.Load())
	}

	registry.Remove(oldSession)

	got, exists := registry.Get(newSession.PeerID)
	if !exists || got != newSession {
		t.Fatal("removing the old session removed its replacement")
	}
	if newConn.closed.Load() != 0 {
		t.Fatal("replacement connection was closed")
	}
}
