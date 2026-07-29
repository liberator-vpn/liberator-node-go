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

func (s *PeersSyncServer) SubscribeClients(_ *emptypb.Empty, stream grpc.ServerStreamingServer[proto.ClientEvent]) error {
	ctx := stream.Context()

	updateCh, unsubscribe := s.router.SubscribeEvents(ctx)
	defer unsubscribe()

	if err := stream.Send(s.buildSyncEvent()); err != nil {
		return err
	}

	ticker := time.NewTicker(SyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-ticker.C:
			if err := stream.Send(s.buildSyncEvent()); err != nil {
				return err
			}

		case upd, ok := <-updateCh:
			if !ok {
				return nil
			}
			if err := stream.Send(s.generateEvent(upd)); err != nil {
				return err
			}
		}
	}
}

func (s *PeersSyncServer) generateEvent(update router.RouterEvent) *proto.ClientEvent {
	event := &proto.ClientEvent{
		Update: &proto.ClientInfo{
			NodeId:    update.NodeID,
			VirtualIp: update.VirtualIP,
		},
	}

	switch update.Type {
	case router.EventType_ClientConnected:
		event.Type = proto.ClientEventType_CLIENT_EVENT_CONNECTED
	case router.EventType_ClientDisconnected:
		event.Type = proto.ClientEventType_CLIENT_EVENT_DISCONNECTED
	}
	return event
}

func (s *PeersSyncServer) buildSyncEvent() *proto.ClientEvent {
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
