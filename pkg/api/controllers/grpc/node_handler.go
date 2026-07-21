package grpc

import (
	"context"

	"google.golang.org/grpc"

	pb "github.com/TexHik620953/liberator-node-go/pkg/api/grpc" // Наш сгенерированный gRPC пакет
)

type NodeHandler struct {
	pb.UnimplementedNodeServiceServer
	nodeID string
}

func RegisterNodeService(server *grpc.Server, nodeID string) {
	handler := &NodeHandler{
		nodeID: nodeID,
	}
	pb.RegisterNodeServiceServer(server, handler)
}

func (nh *NodeHandler) Ping(ctx context.Context, rq *pb.PingMessage) (*pb.PongMessage, error) {
	return &pb.PongMessage{
		NodeId: nh.nodeID,
	}, nil
}
