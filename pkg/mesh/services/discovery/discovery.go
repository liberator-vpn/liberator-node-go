package discovery

import (
	"context"

	"liberator-node-go/internal/utils/peerstore"
	"liberator-node-go/pkg/mesh/services/discovery/proto"

	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type DiscoveryService struct {
	proto.DiscoveryServiceServer

	peerStore *peerstore.PeerStore
}

func New(grpcServer *grpc.Server, peerStore *peerstore.PeerStore) *DiscoveryService {
	svc := &DiscoveryService{
		peerStore: peerStore,
	}
	proto.RegisterDiscoveryServiceServer(grpcServer, svc)
	return svc
}

// MeshService grpc implementation
func (svc *DiscoveryService) PullKnownPeers(ctx context.Context, _ *emptypb.Empty) (*proto.ListKnownPeersResponse, error) {
	resp := &proto.ListKnownPeersResponse{
		Peers: make([]*proto.PeerInfo, 0),
	}

	for _, peer := range svc.peerStore.List() {
		pi := &proto.PeerInfo{
			Id:       peer.Id,
			LastSeen: peer.LastSeen.Unix(),
			Addr:     peer.Address,
		}
		resp.Peers = append(resp.Peers, pi)
	}
	return resp, nil
}

func (svc *DiscoveryService) RunOnConnection(ctx context.Context, client *grpc.ClientConn) error {
	discoveryClient := proto.NewDiscoveryServiceClient(client)
	rp, err := discoveryClient.PullKnownPeers(ctx, &emptypb.Empty{})
	if err != nil {
		return err
	}
	for _, peer := range rp.Peers {
		pi := &peerstore.PeerInfo{
			Id:       peer.Id,
			LastSeen: time.Unix(peer.LastSeen, 0),
			Address:  peer.Addr,
		}
		svc.peerStore.InsertMerge(pi)
	}

	return nil
}

func (svc *DiscoveryService) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Second * 1)

	// Pull updates
	go func() {
		for range ticker.C {
			for _, rec := range svc.peerStore.ListConnected() {
				resp, err := proto.NewDiscoveryServiceClient(rec.Connection.GrpcClient()).PullKnownPeers(ctx, &emptypb.Empty{})
				if err != nil {
					log.Printf("failed to discover: %v", err)
					continue
				}
				for _, peer := range resp.Peers {
					svc.peerStore.InsertMerge(&peerstore.PeerInfo{
						Id:       peer.Id,
						LastSeen: time.Unix(peer.LastSeen, 0),
						Address:  peer.Addr,
					})
				}
			}
		}
	}()

	<-ctx.Done()
	ticker.Stop()
}
