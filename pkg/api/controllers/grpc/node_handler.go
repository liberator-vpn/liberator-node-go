package grpc

import (
	"context"

	"google.golang.org/grpc"

	"github.com/TexHik620953/liberator-node-go/internal/infra/ipapi"
	pb "github.com/TexHik620953/liberator-node-go/pkg/api/grpc" // Наш сгенерированный gRPC пакет
)

type NodeHandler struct {
	pb.UnimplementedNodeServiceServer
	nodeID string
	ipInfo ipapi.IpInfo
}

func RegisterNodeService(server *grpc.Server, nodeID string, ipInfo ipapi.IpInfo) {
	handler := &NodeHandler{
		nodeID: nodeID,
		ipInfo: ipInfo,
	}
	pb.RegisterNodeServiceServer(server, handler)
}

func (nh *NodeHandler) Ping(ctx context.Context, rq *pb.PingMessage) (*pb.PongMessage, error) {
	return &pb.PongMessage{
		NodeId:      nh.nodeID,
		CountryCode: nh.ipInfo.CountryCode,
	}, nil
}
