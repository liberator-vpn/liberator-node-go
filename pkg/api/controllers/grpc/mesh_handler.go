package grpc

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/TexHik620953/liberator-node-go/pkg/api/grpc" // Наш сгенерированный gRPC пакет
	"github.com/TexHik620953/liberator-node-go/pkg/model"
)

type MeshNode interface {
	GetConnectivity() []model.ConnectivityState
}

type MeshHandler struct {
	pb.UnimplementedMeshServiceServer
	node MeshNode
}

func RegisterMeshService(
	server *grpc.Server,
	node MeshNode,
) {
	handler := &MeshHandler{
		node: node,
	}
	pb.RegisterMeshServiceServer(server, handler)
}

func (mh *MeshHandler) ListConnectedNodes(context.Context, *emptypb.Empty) (*pb.ListNodesResponse, error) {
	stats := mh.node.GetConnectivity()

	resp := &pb.ListNodesResponse{
		Nodes: make([]*pb.ConnectedNodeInfo, len(stats)),
	}

	for i, v := range stats {
		resp.Nodes[i] = &pb.ConnectedNodeInfo{
			Id:        v.Id,
			Address:   v.Addr,
			TotalRecv: v.TotalRecv,
			TotalSent: v.TotalSent,
		}
	}
	return resp, nil
}
