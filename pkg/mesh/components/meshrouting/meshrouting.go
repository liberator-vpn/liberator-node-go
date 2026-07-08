package meshrouting

import (
	"context"
	"liberator-node-go/internal/utils/routingtable"
	"liberator-node-go/pkg/mesh/components/meshrouting/proto"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type MeshRoutingService struct {
	routingTable routingtable.RoutingTable
	proto.MeshRoutingServiceServer
}

func New(grpcServer *grpc.Server, routingTable routingtable.RoutingTable) (*MeshRoutingService, error) {
	mr := &MeshRoutingService{
		routingTable: routingTable,
	}

	proto.RegisterMeshRoutingServiceServer(grpcServer, mr)
	return mr, nil
}

func (mr *MeshRoutingService) SendConnectionUpdate(ctx context.Context, rq *proto.UserConnectionUpdate) (*emptypb.Empty, error) {
	return nil, nil
}
func (mr *MeshRoutingService) PullFullTable(ctx context.Context, _ *emptypb.Empty) (*proto.UsersConnectionsList, error) {
	return nil, nil
}
