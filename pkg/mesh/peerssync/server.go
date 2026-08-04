package peerssync

import (
	"time"

	"github.com/TexHik620953/liberator-node-go/pkg/mesh/peerssync/proto"
	"github.com/TexHik620953/liberator-node-go/pkg/router"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

const SyncInterval = time.Second * 30

type PeersSyncServer struct {
	proto.UnimplementedPeersSyncServiceServer
	router Router
}

func RegisterPeersSyncServer(grpcServer *grpc.Server, router Router) {
	srv := &PeersSyncServer{router: router}
	proto.RegisterPeersSyncServiceServer(grpcServer, srv)
}

// Rules
func (s *PeersSyncServer) SubscribeClientsRules(_ *emptypb.Empty, stream grpc.ServerStreamingServer[proto.ClientRuleEvent]) error {
	ctx := stream.Context()

	firewallUpdateCh, unsubscribeFirewall := s.router.SubscribeFirewallEvents(ctx)
	defer unsubscribeFirewall()

	if err := stream.Send(s.buildFirewallSyncEvent()); err != nil {
		return err
	}

	ticker := time.NewTicker(SyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-ticker.C:
			if err := stream.Send(s.buildFirewallSyncEvent()); err != nil {
				return err
			}

		case upd, ok := <-firewallUpdateCh:
			if !ok {
				return nil
			}
			if err := stream.Send(s.generateFirewallEvent(upd)); err != nil {
				return err
			}
		}
	}
}

func (s *PeersSyncServer) generateFirewallEvent(update router.FirewallEvent) *proto.ClientRuleEvent {
	event := &proto.ClientRuleEvent{
		Update: &proto.ClientRule{
			NodeId: update.NodeID,
			Id:     update.RuleID,
		},
	}

	switch update.Type {
	case router.FirewallEventType_RuleAdded:
		event.Type = proto.ClientRuleEventType_CLIENT_RULE_EVENT_ADDED
		event.Update.Addr = update.Address
		event.Update.TargetAddr = update.TargetAddress
		event.Update.Protocol = update.Protocol
		event.Update.PortRangeStart = uint32(update.PortRangeStart)
		if update.PortRangeEnd != nil {
			v := uint32(*update.PortRangeEnd)
			event.Update.PortRangeEnd = &v
		}
	case router.FirewallEventType_RuleRemoved:
		event.Type = proto.ClientRuleEventType_CLIENT_RULE_EVENT_REMOVED
	}
	return event
}

func (s *PeersSyncServer) buildFirewallSyncEvent() *proto.ClientRuleEvent {
	all := s.router.DumpRules()

	dump := make([]*proto.ClientRule, 0, len(all))
	for _, p := range all {

		var portRangeEnd *uint32
		if p.PortRangeEnd != nil {
			v := uint32(*p.PortRangeEnd)
			portRangeEnd = &v
		}
		dump = append(dump, &proto.ClientRule{
			NodeId: p.NodeID,
			Id:     p.RuleID,

			Addr:           p.Address,
			TargetAddr:     p.TargetAddress,
			Protocol:       p.Protocol,
			PortRangeStart: uint32(p.PortRangeStart),
			PortRangeEnd:   portRangeEnd,
		})
	}
	return &proto.ClientRuleEvent{
		Type: proto.ClientRuleEventType_CLIENT_RULE_EVENT_SYNC,
		Dump: dump,
	}
}

// Clients
func (s *PeersSyncServer) SubscribeClients(_ *emptypb.Empty, stream grpc.ServerStreamingServer[proto.ClientEvent]) error {
	ctx := stream.Context()

	routingUpdateCh, unsubscribeRouting := s.router.SubscribeRoutingEvents(ctx)
	defer unsubscribeRouting()

	if err := stream.Send(s.buildRoutingSyncEvent()); err != nil {
		return err
	}

	ticker := time.NewTicker(SyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-ticker.C:
			if err := stream.Send(s.buildRoutingSyncEvent()); err != nil {
				return err
			}

		case upd, ok := <-routingUpdateCh:
			if !ok {
				return nil
			}
			if err := stream.Send(s.generateRoutingeEvent(upd)); err != nil {
				return err
			}
		}
	}
}

func (s *PeersSyncServer) generateRoutingeEvent(update router.RouterEvent) *proto.ClientEvent {
	event := &proto.ClientEvent{
		Update: &proto.ClientInfo{
			NodeId:    update.NodeID,
			VirtualIp: update.VirtualIP,
		},
	}

	switch update.Type {
	case router.RouterEventType_ClientAdded:
		event.Type = proto.ClientEventType_CLIENT_EVENT_ADDED
	case router.RouterEventType_ClientRemoved:
		event.Type = proto.ClientEventType_CLIENT_EVENT_REMOVED
	}
	return event
}

func (s *PeersSyncServer) buildRoutingSyncEvent() *proto.ClientEvent {
	all := s.router.DumpRoutingTable()

	dump := make([]*proto.ClientInfo, 0, len(all))
	for _, p := range all {
		dump = append(dump, &proto.ClientInfo{
			NodeId:    p.NodeID,
			VirtualIp: p.VirtualIP,
		})
	}
	return &proto.ClientEvent{
		Type: proto.ClientEventType_CLIENT_EVENT_SYNC,
		Dump: dump,
	}
}
