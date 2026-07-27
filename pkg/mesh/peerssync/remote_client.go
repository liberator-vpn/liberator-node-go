package peerssync

import (
	"context"

	"github.com/TexHik620953/liberator-node-go/pkg/routingtable"
)

type RemoteMessage struct {
	TargetNodeID    string
	TargetVirtualIP uint32
	Data            []byte
}

// Static check
var _ routingtable.RoutingObject = (*RemoteClient)(nil)

type RemoteClient struct {
	ctx          context.Context
	nodeID       string
	virtualIP    uint32
	toMeshClient chan RemoteMessage
}

func newRemoteClient(ctx context.Context, virtualIP uint32, nodeID string, toMeshClient chan RemoteMessage) *RemoteClient {
	return &RemoteClient{
		ctx:          ctx,
		nodeID:       nodeID,
		virtualIP:    virtualIP,
		toMeshClient: toMeshClient,
	}
}

// Context implements [routingtable.RoutingObject].
func (r *RemoteClient) Context() context.Context {
	return r.ctx
}

// GetNodeID implements [routingtable.RoutingObject].
func (r *RemoteClient) GetNodeID() string {
	return r.nodeID
}

// GetVirtualIP implements [routingtable.RoutingObject].
func (r *RemoteClient) GetVirtualIP() uint32 {
	return r.virtualIP
}

// SendDatagram implements [routingtable.RoutingObject].
func (r *RemoteClient) SendDatagram(data []byte) error {
	select {
	case r.toMeshClient <- RemoteMessage{
		TargetNodeID:    r.nodeID,
		TargetVirtualIP: r.virtualIP,
		Data:            data,
	}:
		return nil
	case <-r.ctx.Done():
		return r.ctx.Err()
	}
}
