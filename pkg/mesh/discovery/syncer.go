package discovery

import (
	"context"
	"strings"
	"time"

	"github.com/TexHik620953/liberator-node-go/pkg/mesh/discovery/proto"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/session"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/topology"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/transport"
	"google.golang.org/protobuf/types/known/emptypb"
)

type DiscoverySyncer struct {
	repo           topology.PeerRepository
	registry       session.Registry
	engine         *session.SessionEngine
	transport      transport.NetworkTransport
	bootstrapAddrs []string
	localID        string // <--- Добавим локальный ID ноды для Tie-Breaking
}

func NewDiscoverySyncer(
	repo topology.PeerRepository,
	reg session.Registry,
	engine *session.SessionEngine,
	tr transport.NetworkTransport,
	bootstrap []string,
	localID string,
) *DiscoverySyncer {
	return &DiscoverySyncer{
		repo:           repo,
		registry:       reg,
		engine:         engine,
		transport:      tr,
		bootstrapAddrs: bootstrap,
		localID:        localID,
	}
}

func (ds *DiscoverySyncer) Start(ctx context.Context) {
	go ds.listenForNewSessions(ctx)
	go ds.listenForNewPeers(ctx)
	go ds.connectToBootstrap(ctx)

	ticker := time.NewTicker(5 * time.Second) // Уменьшим тикер для ускорения схождения теста
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			peers := ds.repo.List()
			for _, p := range peers {
				if _, active := ds.registry.Get(p.ID); active {
					continue
				}

				if !strings.HasPrefix(p.ID, "bootstrap:") && ds.localID < p.ID {
					continue
				}

				go ds.connect(ctx, p.Address)
			}
		}
	}
}

func (ds *DiscoverySyncer) connectToBootstrap(ctx context.Context) {
	for _, addr := range ds.bootstrapAddrs {
		// Дополнительная проверка безопасности: не подключаемся к собственному порту
		if tAddr := ds.transport.Addr(); tAddr != nil && strings.Contains(tAddr.String(), addr) {
			continue
		}
		go ds.connect(ctx, addr)
	}
}

func (ds *DiscoverySyncer) listenForNewPeers(ctx context.Context) {
	eventCh, unsubscribe := ds.repo.Subscribe(ctx)
	defer unsubscribe()

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-eventCh:
			if !ok {
				return
			}
			if ev.Type != proto.PeerEventType_PEER_EVENT_JOINED || ev.Update == nil {
				continue
			}

			// ИСПРАВЛЕНИЕ: Локальные бутстрап-строки не должны триггерить сетевой Dial
			if strings.HasPrefix(ev.Update.Id, "bootstrap:") {
				continue
			}

			if _, active := ds.registry.Get(ev.Update.Id); active {
				continue
			}

			// Проверка Tie-Breaking для реактивного коннекта
			if ds.localID < ev.Update.Id {
				continue
			}

			go ds.connect(ctx, ev.Update.Addr)
		}
	}
}

func (ds *DiscoverySyncer) listenForNewSessions(ctx context.Context) {
	sessionCh := ds.registry.SubscribeNewSessions(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case s, ok := <-sessionCh:
			if !ok {
				return
			}
			// Запускаем двусторонний gRPC-стрим для выкачивания топологии
			go ds.syncDiscoveryData(ctx, s)
		}
	}
}

func (ds *DiscoverySyncer) connect(ctx context.Context, addr string) {
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	pConn, err := ds.transport.Dial(dialCtx, addr)
	if err != nil {
		return
	}

	// Передаем в движок сессий — он сохранит её в реестр, что автоматически
	// стриггерит событие в listenForNewSessions для запуска syncDiscoveryData
	ds.engine.HandleConnection(ctx, pConn)
}

func (ds *DiscoverySyncer) syncDiscoveryData(ctx context.Context, s *session.Session) {
	client := proto.NewDiscoveryServiceClient(s.GrpcClient)
	stream, err := client.SubscribePeers(ctx, &emptypb.Empty{})
	if err != nil {
		return
	}

	for {
		ev, err := stream.Recv()
		if err != nil {
			return
		}

		if ev.Type == proto.PeerEventType_PEER_EVENT_SYNC {
			for _, p := range ev.Dump {
				// ИСПРАВЛЕНИЕ: Строго запрещаем импорт временных bootstrap-строк от соседей
				if strings.HasPrefix(p.Id, "bootstrap:") {
					continue
				}
				ds.repo.InsertMerge(topology.PeerInfo{
					ID:       p.Id,
					Address:  p.Addr,
					LastSeen: time.Unix(0, p.LastSeen),
				})
			}
		} else if ev.Update != nil {
			// ИСПРАВЛЕНИЕ: Строго запрещаем импорт дельт с временными bootstrap-строками
			if strings.HasPrefix(ev.Update.Id, "bootstrap:") {
				continue
			}
			ds.repo.InsertMerge(topology.PeerInfo{
				ID:       ev.Update.Id,
				Address:  ev.Update.Addr,
				LastSeen: time.Unix(0, ev.Update.LastSeen),
			})
		}
	}
}
