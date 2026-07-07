package discovery

import (
	"context"
	"maps"

	"liberator-node-go/internal/infra/ipapi"
	"liberator-node-go/internal/utils/safemap"
	"liberator-node-go/pkg/mesh/discovery/proto"

	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Connection interface {
	GrpcClient() *grpc.ClientConn
}

type DiscoveryService[T Connection] struct {
	proto.DiscoveryServiceServer

	peerStore *PeerStore

	connections safemap.Safemap[string, T]
}

func New[T Connection](grpcServer *grpc.Server, peerStore *PeerStore, connections safemap.Safemap[string, T]) *DiscoveryService[T] {
	svc := &DiscoveryService[T]{
		peerStore:   peerStore,
		connections: connections,
	}
	proto.RegisterDiscoveryServiceServer(grpcServer, svc)
	return svc
}

// MeshService grpc implementation
func (svc *DiscoveryService[T]) PullKnownPeers(ctx context.Context, _ *emptypb.Empty) (*proto.ListKnownPeersResponse, error) {
	resp := &proto.ListKnownPeersResponse{
		Peers: make([]*proto.PeerInfo, 0),
	}
	for _, peer := range svc.peerStore.List() {
		var ipInfo *proto.IpInfo
		if peer.IpInfo != nil {
			ipInfo = &proto.IpInfo{
				Country:     peer.IpInfo.Country,
				CountryCode: peer.IpInfo.CountryCode,
				Region:      peer.IpInfo.Region,
				RegionName:  peer.IpInfo.RegionName,
				City:        peer.IpInfo.City,
				Zip:         peer.IpInfo.Zip,
				Lat:         peer.IpInfo.Lat,
				Lon:         peer.IpInfo.Lon,
				Timezone:    peer.IpInfo.Timezone,
				Isp:         peer.IpInfo.Isp,
				Org:         peer.IpInfo.Org,
				As:          peer.IpInfo.As,
				Query:       peer.IpInfo.As,
			}
		}
		pi := &proto.PeerInfo{
			Id:       peer.Id,
			LastSeen: peer.LastSeen.Unix(),
			IpInfo:   ipInfo,
			Addr:     maps.Clone(peer.Addresses),
		}
		resp.Peers = append(resp.Peers, pi)
	}
	return resp, nil
}

func (svc *DiscoveryService[T]) RunOnConnection(ctx context.Context, client *grpc.ClientConn) error {
	discoveryClient := proto.NewDiscoveryServiceClient(client)
	rp, err := discoveryClient.PullKnownPeers(ctx, &emptypb.Empty{})
	if err != nil {
		return err
	}
	for _, peer := range rp.Peers {
		var ipInfo *ipapi.IpInfo
		if peer.IpInfo != nil {
			ipInfo = &ipapi.IpInfo{
				Country:     peer.IpInfo.Country,
				CountryCode: peer.IpInfo.CountryCode,
				Region:      peer.IpInfo.Region,
				RegionName:  peer.IpInfo.RegionName,
				City:        peer.IpInfo.City,
				Zip:         peer.IpInfo.Zip,
				Lat:         peer.IpInfo.Lat,
				Lon:         peer.IpInfo.Lon,
				Timezone:    peer.IpInfo.Timezone,
				Isp:         peer.IpInfo.Isp,
				Org:         peer.IpInfo.Org,
				As:          peer.IpInfo.As,
				Query:       peer.IpInfo.Query,
			}
		}
		pi := &PeerInfo{
			Id:        peer.Id,
			LastSeen:  time.Unix(peer.LastSeen, 0),
			IpInfo:    ipInfo,
			Addresses: maps.Clone(peer.Addr),
		}
		svc.peerStore.InsertMerge(pi)
	}

	return nil
}

func (svc *DiscoveryService[T]) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Second * 1)
	go func() {
		for range ticker.C {
			for _, mc := range svc.connections.CloneRaw() {
				resp, err := proto.NewDiscoveryServiceClient(mc.GrpcClient()).PullKnownPeers(ctx, &emptypb.Empty{})
				if err != nil {
					log.Printf("failed to discover: %v", err)
					return
				}
				for _, peer := range resp.Peers {
					var ipInfo *ipapi.IpInfo
					if peer.IpInfo != nil {
						ipInfo = &ipapi.IpInfo{
							Country:     peer.IpInfo.Country,
							CountryCode: peer.IpInfo.CountryCode,
							Region:      peer.IpInfo.Region,
							RegionName:  peer.IpInfo.RegionName,
							City:        peer.IpInfo.City,
							Zip:         peer.IpInfo.Zip,
							Lat:         peer.IpInfo.Lat,
							Lon:         peer.IpInfo.Lon,
							Timezone:    peer.IpInfo.Timezone,
							Isp:         peer.IpInfo.Isp,
							Org:         peer.IpInfo.Org,
							As:          peer.IpInfo.As,
							Query:       peer.IpInfo.Query,
						}
					}
					pi := &PeerInfo{
						Id:        peer.Id,
						LastSeen:  time.Unix(peer.LastSeen, 0),
						IpInfo:    ipInfo,
						Addresses: maps.Clone(peer.Addr),
					}

					svc.peerStore.InsertMerge(pi)
				}
			}
		}
	}()

	<-ctx.Done()
	ticker.Stop()
}
