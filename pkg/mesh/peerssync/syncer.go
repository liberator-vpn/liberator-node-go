package peerssync

import (
	"context"
	"log"

	"github.com/TexHik620953/liberator-node-go/pkg/mesh/peerssync/proto"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/session"
	"google.golang.org/protobuf/types/known/emptypb"
)

type PeersSyncSyncer struct {
	ctx          context.Context
	registry     session.Registry
	localID      string
	router       Router
	toMeshClient chan RemoteMessage
}

func NewPeersSyncSyncer(
	ctx context.Context,
	registry session.Registry,
	router Router,
	localID string,
	toMeshClient chan RemoteMessage,
) *PeersSyncSyncer {
	return &PeersSyncSyncer{
		ctx:          ctx,
		registry:     registry,
		router:       router,
		localID:      localID,
		toMeshClient: toMeshClient,
	}
}

func (ds *PeersSyncSyncer) Start(ctx context.Context) {
	go func() {
		sessionCh := ds.registry.SubscribeNewSessions(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case s, ok := <-sessionCh:
				if !ok {
					return
				}
				go ds.syncDiscoveryData(ctx, s)
			}
		}
	}()
}

func (ds *PeersSyncSyncer) syncDiscoveryData(ctx context.Context, s *session.Session) {
	client := proto.NewPeersSyncServiceClient(s.GrpcClient)
	stream, err := client.SubscribeClients(ctx, &emptypb.Empty{})
	if err != nil {
		return
	}

	for {
		ev, err := stream.Recv()
		if err != nil {
			return
		}

		switch ev.Type {
		case proto.ClientEventType_CLIENT_EVENT_SYNC:
			for _, v := range ev.Dump {
				ds.syncObject(v)
			}
		case proto.ClientEventType_CLIENT_EVENT_CONNECTED:
			if ev.Update == nil {
				continue
			}
			ds.addRemoteRoutingObject(ev.Update)
		case proto.ClientEventType_CLIENT_EVENT_DISCONNECTED:
			if ev.Update == nil {
				continue
			}
			ds.deleteRemoteRoutingObject(ev.Update)
		}
	}
}

func (ds *PeersSyncSyncer) syncObject(ev *proto.ClientInfo) {
	obj, ex := ds.router.GetRemoteRoutingObject(ev.VirtualIp)
	if !ex {
		ds.addRemoteRoutingObject(ev)
		return
	}

	if obj.GetNodeID() != ev.NodeId {
		ds.deleteRemoteRoutingObject(ev)
		ds.addRemoteRoutingObject(ev)
	}
}
func (ds *PeersSyncSyncer) addRemoteRoutingObject(ev *proto.ClientInfo) {
	obj := newRemoteClient(ds.ctx, ev.VirtualIp, ev.NodeId, ds.toMeshClient)
	if err := ds.router.AddRemoteRoutingObject(obj); err != nil {
		log.Printf("failed to add remote routing object: %v", err)
	}
}

func (ds *PeersSyncSyncer) deleteRemoteRoutingObject(ev *proto.ClientInfo) {
	if err := ds.router.DeleteRemoteRoutingObject(ev.VirtualIp); err != nil {
		log.Printf("failed to delete remote routing object: %v", err)
	}
}
