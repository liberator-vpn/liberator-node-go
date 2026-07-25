package discovery

import (
	"context"
	"time"

	"github.com/TexHik620953/liberator-node-go/pkg/mesh/discovery/proto"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type DiscoveryClient interface {
	Subscribe(ctx context.Context, grpcClient *grpc.ClientConn) (<-chan *proto.PeerEvent, error)
}

type discoveryClient struct {
	backoffBase time.Duration
	maxBackoff  time.Duration
}

func NewDiscoveryClient() DiscoveryClient {
	return &discoveryClient{
		backoffBase: 1 * time.Second,
		maxBackoff:  1 * time.Minute,
	}
}

func (c *discoveryClient) Subscribe(ctx context.Context, grpcClient *grpc.ClientConn) (<-chan *proto.PeerEvent, error) {
	client := proto.NewDiscoveryServiceClient(grpcClient)
	eventCh := make(chan *proto.PeerEvent, 100)

	go func() {
		defer close(eventCh)
		backoff := c.backoffBase

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			stream, err := client.SubscribePeers(ctx, &emptypb.Empty{})
			if err != nil {
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
				}
				backoff *= 2
				if backoff > c.maxBackoff {
					backoff = c.maxBackoff
				}
				continue
			}

			backoff = c.backoffBase

			for {
				ev, err := stream.Recv()
				if err != nil {
					select {
					case <-ctx.Done():
						return
					case <-time.After(backoff):
					}
					backoff *= 2
					if backoff > c.maxBackoff {
						backoff = c.maxBackoff
					}
					break
				}
				select {
				case eventCh <- ev:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return eventCh, nil
}
