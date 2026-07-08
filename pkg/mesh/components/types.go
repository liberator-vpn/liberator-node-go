package components

import "google.golang.org/grpc"

type Connection interface {
	GrpcClient() *grpc.ClientConn
}
