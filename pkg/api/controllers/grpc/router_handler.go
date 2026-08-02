package grpc

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/TexHik620953/liberator-node-go/pkg/api/grpc" // Наш сгенерированный gRPC пакет
	"github.com/TexHik620953/liberator-node-go/pkg/model"
)

type Router interface {
	GetStats() model.RouterStats
}

type RouterHandler struct {
	pb.UnimplementedRouterServiceServer
	router Router
}

func RegisterRouterService(
	server *grpc.Server,
	router Router,
) {
	handler := &RouterHandler{
		router: router,
	}
	pb.RegisterRouterServiceServer(server, handler)
}

func (rh *RouterHandler) GetStats(context.Context, *emptypb.Empty) (*pb.RouterStats, error) {
	stats := rh.router.GetStats()

	return &pb.RouterStats{
		TotalFromIface: stats.TotalFromIface,
		TotalFromMesh:  stats.TotalFromMesh,
		TotalFromPeers: stats.TotalFromPeers,
	}, nil
}
