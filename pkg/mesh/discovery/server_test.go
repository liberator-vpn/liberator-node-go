package discovery

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/TexHik620953/liberator-node-go/pkg/mesh/discovery/proto"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/topology"
	"google.golang.org/grpc/metadata"
)

type serverTestRepository struct {
	mu       sync.Mutex
	eventCh  chan *proto.PeerEvent
	listOnce sync.Once
}

func (r *serverTestRepository) InsertMerge(topology.PeerInfo) bool {
	return false
}

func (r *serverTestRepository) Get(string) (topology.PeerInfo, bool) {
	return topology.PeerInfo{}, false
}

func (r *serverTestRepository) List() []topology.PeerInfo {
	r.mu.Lock()
	eventCh := r.eventCh
	r.mu.Unlock()
	r.listOnce.Do(func() {
		if eventCh != nil {
			eventCh <- &proto.PeerEvent{
				Type: proto.PeerEventType_PEER_EVENT_JOINED,
				Update: &proto.PeerInfo{
					Id:   "joined",
					Addr: "127.0.0.1:9000",
				},
			}
		}
	})
	return nil
}

func (r *serverTestRepository) Remove(string) {}

func (r *serverTestRepository) Count() int {
	return 0
}

func (r *serverTestRepository) Subscribe(context.Context) (<-chan *proto.PeerEvent, context.CancelFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.eventCh = make(chan *proto.PeerEvent, 1)
	return r.eventCh, func() {}
}

type serverTestStream struct {
	ctx    context.Context
	events chan *proto.PeerEvent
}

func (s *serverTestStream) Send(event *proto.PeerEvent) error {
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

func TestSubscribePeersDoesNotLoseEventDuringSnapshot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	repo := &serverTestRepository{}
	stream := &serverTestStream{
		ctx:    ctx,
		events: make(chan *proto.PeerEvent, 2),
	}
	server := &DiscoveryServer{repo: repo}

	done := make(chan error, 1)
	go func() {
		done <- server.SubscribePeers(nil, stream)
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
