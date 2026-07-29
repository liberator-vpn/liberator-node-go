package discovery

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TexHik620953/liberator-node-go/pkg/mesh/transport"
)

type blockingTransport struct {
	calls   atomic.Int32
	started chan struct{}
	once    sync.Once
}

func (t *blockingTransport) Dial(ctx context.Context, _ string) (transport.PeerConnection, error) {
	t.calls.Add(1)
	t.once.Do(func() {
		close(t.started)
	})
	<-ctx.Done()
	return nil, ctx.Err()
}

func (t *blockingTransport) Accept(ctx context.Context) (transport.PeerConnection, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (t *blockingTransport) Addr() net.Addr {
	return testAddress("local")
}

func (t *blockingTransport) Close() error {
	return nil
}

type testAddress string

func (a testAddress) Network() string {
	return "test"
}

func (a testAddress) String() string {
	return string(a)
}

func TestConnectCoalescesConcurrentDials(t *testing.T) {
	tr := &blockingTransport{started: make(chan struct{})}
	syncer := &DiscoverySyncer{
		transport: tr,
		dialing:   make(map[string]struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())

	firstDone := make(chan struct{})
	go func() {
		syncer.connect(ctx, "peer:9000")
		close(firstDone)
	}()
	<-tr.started

	secondDone := make(chan struct{})
	go func() {
		syncer.connect(ctx, "peer:9000")
		close(secondDone)
	}()

	select {
	case <-secondDone:
	case <-time.After(time.Second):
		t.Fatal("duplicate dial did not return")
	}
	if tr.calls.Load() != 1 {
		t.Fatalf("dial calls: got %d, want 1", tr.calls.Load())
	}

	cancel()
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("active dial did not stop after cancellation")
	}
}
