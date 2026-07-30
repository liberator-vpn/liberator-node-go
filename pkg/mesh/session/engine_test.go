package session

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/TexHik620953/liberator-node-go/internal/utils/dgmessage"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/topology"
)

type engineTestRouter struct{}

func (engineTestRouter) NewMessageCopyFrom([]byte) (*dgmessage.DatagramMessage, error) {
	return nil, nil
}

func (engineTestRouter) HandleMeshPacket(*dgmessage.DatagramMessage) {}

type engineTestPusher struct{}

func (engineTestPusher) PushConnection(conn net.Conn) {
	_ = conn.Close()
}

func TestHandleConnectionDoesNotBlockAcceptLoop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	registry := NewRegistry("local")
	repo := topology.NewPeerRepository(ctx, topology.NewJsonFilePersister(""))
	engine := NewSessionEngine(registry, engineTestPusher{}, repo, engineTestRouter{})
	conn := &registryTestConnection{}

	done := make(chan struct{})
	go func() {
		engine.HandleConnection(ctx, conn)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("HandleConnection blocked while the session was active")
	}

	if active, exists := registry.Get(conn.ID()); !exists || active.Conn != conn {
		t.Fatal("connection was not registered")
	}
}
