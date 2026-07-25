package discovery

import (
	"time"

	"github.com/TexHik620953/liberator-node-go/pkg/mesh/discovery/proto"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/peerstore"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type DiscoveryService struct {
	proto.UnimplementedDiscoveryServiceServer
	peerStore *peerstore.PeerStore
}

func NewDiscoveryService(grpcServer *grpc.Server, ps *peerstore.PeerStore) *DiscoveryService {
	svc := &DiscoveryService{peerStore: ps}
	proto.RegisterDiscoveryServiceServer(grpcServer, svc)
	return svc
}

func (s *DiscoveryService) buildSyncEvent() *proto.PeerEvent {
	all := s.peerStore.List()
	dump := make([]*proto.PeerInfo, 0, len(all))
	for _, p := range all {
		dump = append(dump, &proto.PeerInfo{
			Id:       p.Id,
			Addr:     p.Address,
			LastSeen: p.LastSeen.UnixNano(),
		})
	}
	return &proto.PeerEvent{
		Type: proto.PeerEventType_PEER_EVENT_SYNC,
		Dump: dump,
	}
}

func (s *DiscoveryService) SubscribePeers(_ *emptypb.Empty, stream grpc.ServerStreamingServer[proto.PeerEvent]) error {
	ctx := stream.Context()

	if err := stream.Send(s.buildSyncEvent()); err != nil {
		return err
	}

	eventCh, unsubscribe := s.peerStore.Subscribe(ctx)
	defer unsubscribe()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := stream.Send(s.buildSyncEvent()); err != nil {
				return err
			}
		case ev, ok := <-eventCh:
			if !ok {
				return nil
			}
			if err := stream.Send(ev); err != nil {
				return err
			}
		}
	}
}
