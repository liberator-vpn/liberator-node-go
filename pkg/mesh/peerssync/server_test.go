package peerssync

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/TexHik620953/liberator-node-go/pkg/mesh/peerssync/proto"
	"github.com/TexHik620953/liberator-node-go/pkg/router"
	"github.com/TexHik620953/liberator-node-go/pkg/routingtable"
	"google.golang.org/grpc/metadata"
)

type serverTestRouter struct {
	mu       sync.Mutex
	eventCh  chan router.RouterEvent
	dumpOnce sync.Once
}

func (r *serverTestRouter) SubscribeEvents(context.Context) (<-chan router.RouterEvent, context.CancelFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.eventCh = make(chan router.RouterEvent, 1)
	return r.eventCh, func() {}
}

func (r *serverTestRouter) DumpRoutingTable() []routingtable.RoutingTableRecordDump {
	r.mu.Lock()
	eventCh := r.eventCh
	r.mu.Unlock()
	r.dumpOnce.Do(func() {
		if eventCh != nil {
			eventCh <- router.RouterEvent{
				Type:      router.EventType_ClientConnected,
				NodeID:    "node",
				VirtualIP: 1,
			}
		}
	})
	return nil
}

func (r *serverTestRouter) AddRemoteRoutingObject(routingtable.RoutingObject) error {
	return nil
}

func (r *serverTestRouter) DeleteRemoteRoutingObject(uint32) error {
	return nil
}

func (r *serverTestRouter) GetRemoteRoutingObject(uint32) (routingtable.RoutingObject, bool) {
	return nil, false
}

type serverTestStream struct {
	ctx    context.Context
	events chan *proto.ClientEvent
}

func (s *serverTestStream) Send(event *proto.ClientEvent) error {
	s.events <- event
	return nil
}

func (s *serverTestStream) SetHeader(metadata.MD) error {
	return nil
}

func (s *serverTestStream) SendHeader(metadata.MD) error {
	return nil
}

func (s *serverTestStream) SetTrailer(metadata.MD) {}

func (s *serverTestStream) Context() context.Context {
	return s.ctx
}

func (s *serverTestStream) SendMsg(any) error {
	return nil
}

func (s *serverTestStream) RecvMsg(any) error {
	return nil
}

func TestSubscribeClientsDoesNotLoseEventDuringSnapshot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	testRouter := &serverTestRouter{}
	stream := &serverTestStream{
		ctx:    ctx,
		events: make(chan *proto.ClientEvent, 2),
	}
	server := &PeersSyncServer{router: testRouter}

	done := make(chan error, 1)
	go func() {
		done <- server.SubscribeClients(nil, stream)
	}()

	for i := 0; i < 2; i++ {
		select {
		case <-stream.events:
		case <-time.After(time.Second):
			t.Fatal("event emitted while building the snapshot was lost")
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("subscription did not stop after cancellation")
	}
}
