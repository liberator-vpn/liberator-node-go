package grpc

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/TexHik620953/liberator-node-go/internal/infra/ipapi"
	"github.com/TexHik620953/liberator-node-go/internal/utils/safemap"
	pb "github.com/TexHik620953/liberator-node-go/pkg/api/grpc" // Наш сгенерированный gRPC пакет
	"github.com/TexHik620953/liberator-node-go/pkg/transport"
)

type NodeHandler struct {
	pb.UnimplementedNodeServiceServer
	nodeID     string
	ipInfo     ipapi.IpInfo
	transports safemap.Safemap[string, transport.Transport]
}

func RegisterNodeService(
	server *grpc.Server,
	nodeID string,
	ipInfo ipapi.IpInfo,
	transports safemap.Safemap[string, transport.Transport]) {
	handler := &NodeHandler{
		nodeID:     nodeID,
		ipInfo:     ipInfo,
		transports: transports,
	}
	pb.RegisterNodeServiceServer(server, handler)
}

func (nh *NodeHandler) Ping(ctx context.Context, rq *pb.PingMessage) (*pb.PongMessage, error) {
	return &pb.PongMessage{
		NodeId:      nh.nodeID,
		CountryCode: nh.ipInfo.CountryCode,
	}, nil
}

func (nh *NodeHandler) ListTransportTypes(ctx context.Context, _ *emptypb.Empty) (*pb.ListTransportTypesResponse, error) {
	resp := &pb.ListTransportTypesResponse{
		Types: make([]string, 0),
	}
	nh.transports.Foreach(func(s string, t transport.Transport) {
		resp.Types = append(resp.Types, t.Type())
	})

	return resp, nil
}
