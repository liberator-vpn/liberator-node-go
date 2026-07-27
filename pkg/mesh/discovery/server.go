package discovery

import (
	"strings"
	"time"

	"github.com/TexHik620953/liberator-node-go/pkg/mesh/discovery/proto"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/topology"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

const SyncInterval = time.Second * 30

type DiscoveryServer struct {
	proto.UnimplementedDiscoveryServiceServer
	repo topology.PeerRepository
}

// NewDiscoveryServer создает экземпляр gRPC-сервиса Discovery и регистрирует его
func RegisterDiscoveryService(grpcServer *grpc.Server, repo topology.PeerRepository) {
	srv := &DiscoveryServer{repo: repo}
	proto.RegisterDiscoveryServiceServer(grpcServer, srv)

}

func (s *DiscoveryServer) SubscribePeers(_ *emptypb.Empty, stream proto.DiscoveryService_SubscribePeersServer) error {
	ctx := stream.Context()

	// 1. Сразу отправляем клиенту полный дамп сети (Event Sourcing: Snapshot)
	if err := stream.Send(s.buildSyncEvent()); err != nil {
		return err
	}

	// 2. Подписываемся на динамические изменения в репозитории топологии
	eventCh, unsubscribe := s.repo.Subscribe(ctx)
	defer unsubscribe()

	ticker := time.NewTicker(SyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-ticker.C:
			// Периодически отправляем полный дамп для самовосстановления графа сети у соседа
			if err := stream.Send(s.buildSyncEvent()); err != nil {
				return err
			}

		case ev, ok := <-eventCh:
			if !ok {
				return nil
			}
			// Транслируем дельту (JOINED, LEFT, UPDATED) в gRPC-стрим
			if err := stream.Send(ev); err != nil {
				return err
			}
		}
	}
}

func (s *DiscoveryServer) buildSyncEvent() *proto.PeerEvent {
	all := s.repo.List()
	dump := make([]*proto.PeerInfo, 0, len(all))
	for _, p := range all {
		// ИСПРАВЛЕНИЕ: Никогда не экспортируем временные бутстрап-записи соседям по мешу
		if strings.HasPrefix(p.ID, "bootstrap:") {
			continue
		}
		dump = append(dump, &proto.PeerInfo{
			Id:       p.ID,
			Addr:     p.Address,
			LastSeen: p.LastSeen.UnixNano(),
		})
	}
	return &proto.PeerEvent{
		Type: proto.PeerEventType_PEER_EVENT_SYNC,
		Dump: dump,
	}
}
