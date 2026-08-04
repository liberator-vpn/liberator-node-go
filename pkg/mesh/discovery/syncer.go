package discovery

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/TexHik620953/liberator-node-go/pkg/mesh/discovery/proto"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/session"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/topology"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/transport"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type DiscoverySyncer struct {
	repo           topology.PeerRepository
	registry       session.Registry
	engine         *session.SessionEngine
	transport      transport.NetworkTransport
	bootstrapAddrs []string
	localID        string

	dialMu  sync.Mutex
	dialing map[string]struct{}
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
		dialing:        make(map[string]struct{}),
	}
}

func (ds *DiscoverySyncer) Start(ctx context.Context) {
	go ds.listenForNewSessions(ctx)
	go ds.listenForNewPeers(ctx)
	go ds.connectToBootstrap(ctx)

	ticker := time.NewTicker(5 * time.Second)
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

				if p.ID == ds.localID {
					continue
				}

				go ds.connect(ctx, p.Address)
			}
		}
	}
}

func (ds *DiscoverySyncer) connectToBootstrap(ctx context.Context) {
	for _, addr := range ds.bootstrapAddrs {
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

			if _, active := ds.registry.Get(ev.Update.Id); active {
				continue
			}

			if ds.localID < ev.Update.Id {
				continue
			}
			if ev.Update.Id == ds.localID {
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
			go ds.syncDiscoveryData(ctx, s)
		}
	}
}

func (ds *DiscoverySyncer) connect(ctx context.Context, addr string) {
	if addr == "" || !ds.startDial(addr) {
		return
	}
	defer ds.finishDial(addr)

	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	pConn, err := ds.transport.Dial(dialCtx, addr)
	if err != nil {
		return
	}

	ds.engine.HandleConnection(ctx, pConn, false)
}

func (ds *DiscoverySyncer) startDial(addr string) bool {
	ds.dialMu.Lock()
	defer ds.dialMu.Unlock()

	if _, exists := ds.dialing[addr]; exists {
		return false
	}
	ds.dialing[addr] = struct{}{}
	return true
}

func (ds *DiscoverySyncer) finishDial(addr string) {
	ds.dialMu.Lock()
	delete(ds.dialing, addr)
	ds.dialMu.Unlock()
}

func (ds *DiscoverySyncer) syncDiscoveryData(ctx context.Context, s *session.Session) {
	client := proto.NewDiscoveryServiceClient(s.GrpcClient)
	stream, err := client.SubscribePeers(ctx, &emptypb.Empty{}, grpc.WaitForReady(true))
	if err != nil {
		return
	}

	for {
		ev, err := stream.Recv()
		if err != nil {
			return
		}

		switch ev.Type {
		case proto.PeerEventType_PEER_EVENT_SYNC:
			for _, p := range ev.Dump {
				ds.repo.InsertMerge(topology.PeerInfo{
					ID:       p.Id,
					Address:  p.Addr,
					LastSeen: time.Unix(0, p.LastSeen),
				})
			}
		case proto.PeerEventType_PEER_EVENT_JOINED, proto.PeerEventType_PEER_EVENT_UPDATED:
			if ev.Update == nil {
				continue
			}
			ds.repo.InsertMerge(topology.PeerInfo{
				ID:       ev.Update.Id,
				Address:  ev.Update.Addr,
				LastSeen: time.Unix(0, ev.Update.LastSeen),
			})
		case proto.PeerEventType_PEER_EVENT_LEFT:
			if ev.Update != nil {
				ds.repo.Remove(ev.Update.Id)
			}
		}
	}
}
