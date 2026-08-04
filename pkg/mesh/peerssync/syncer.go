package peerssync

import (
	"context"
	"log"

	"github.com/TexHik620953/liberator-node-go/pkg/firewall"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/peerssync/proto"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/session"
	"google.golang.org/grpc"
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
	sessionCh := ds.registry.SubscribeNewSessions(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case s, ok := <-sessionCh:
			if !ok {
				return
			}
			go ds.syncPeerData(ctx, s)
			go ds.syncPeerRulesData(ctx, s)
		}
	}

}

func (ds *PeersSyncSyncer) syncPeerRulesData(ctx context.Context, s *session.Session) {
	client := proto.NewPeersSyncServiceClient(s.GrpcClient)
	stream, err := client.SubscribeClientsRules(ctx, &emptypb.Empty{}, grpc.WaitForReady(true))

	if err != nil {
		return
	}

	for {
		ev, err := stream.Recv()
		if err != nil {
			return
		}

		switch ev.Type {
		case proto.ClientRuleEventType_CLIENT_RULE_EVENT_SYNC:
			for _, v := range ev.Dump {
				ds.syncRuleObject(v)
			}
		case proto.ClientRuleEventType_CLIENT_RULE_EVENT_ADDED:
			if ev.Update == nil {
				continue
			}
			ds.addRemoteRuleObject(ev.Update)
		case proto.ClientRuleEventType_CLIENT_RULE_EVENT_REMOVED:
			if ev.Update == nil {
				continue
			}
			ds.deleteRemoteRuleObject(ev.Update)
		}
	}
}
func (ds *PeersSyncSyncer) syncRuleObject(ev *proto.ClientRule) {
	ex := ds.router.ExistsRule(firewall.PortRuleIndex{
		NodeID: ev.NodeId,
		RuleID: ev.Id,
	})
	if !ex {
		ds.addRemoteRuleObject(ev)
	}
}
func (ds *PeersSyncSyncer) addRemoteRuleObject(ev *proto.ClientRule) {
	var portRangeEnd *uint16
	if ev.PortRangeEnd != nil {
		v := uint16(*ev.PortRangeEnd)
		portRangeEnd = &v
	}

	ok := ds.router.AddRemoteRule(firewall.PortRuleIndex{
		NodeID: ev.NodeId,
		RuleID: ev.Id,
	},
		firewall.PortRule{
			Address:        ev.Addr,
			TargetAddress:  ev.TargetAddr,
			Protocol:       ev.Protocol,
			PortRangeStart: uint16(ev.PortRangeStart),
			PortRangeEnd:   portRangeEnd,
		})
	if !ok {
		log.Printf("failed to add remote rule")
	}
}
func (ds *PeersSyncSyncer) deleteRemoteRuleObject(ev *proto.ClientRule) {
	if ok := ds.router.RemoveRemoteRule(firewall.PortRuleIndex{
		NodeID: ev.NodeId,
		RuleID: ev.Id,
	}); !ok {
		log.Printf("failed to delete remote rule")
	}
}

func (ds *PeersSyncSyncer) syncPeerData(ctx context.Context, s *session.Session) {
	client := proto.NewPeersSyncServiceClient(s.GrpcClient)
	stream, err := client.SubscribeClients(ctx, &emptypb.Empty{}, grpc.WaitForReady(true))

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
				ds.syncPeerObject(v)
			}
		case proto.ClientEventType_CLIENT_EVENT_ADDED:
			if ev.Update == nil {
				continue
			}
			ds.addRemoteRoutingObject(ev.Update)
		case proto.ClientEventType_CLIENT_EVENT_REMOVED:
			if ev.Update == nil {
				continue
			}
			ds.deleteRemoteRoutingObject(ev.Update)
		}
	}
}
func (ds *PeersSyncSyncer) syncPeerObject(ev *proto.ClientInfo) {
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
