package orchestrator

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/TexHik620953/liberator-node-go/internal/utils/dgmessage"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/discovery"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/discovery/proto"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/peerstore"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/transport"
)

type Router interface {
	HandleMeshPacket(packet *dgmessage.DatagramMessage)
	NewMessageCopyFrom(data []byte) (*dgmessage.DatagramMessage, error)
}

type DiscoveryOrchestrator struct {
	ctx           context.Context
	localID       string
	peerStore     *peerstore.PeerStore
	connManager   transport.ConnectionManager
	discoveryCli  discovery.DiscoveryClient
	connectorTick time.Duration
	router        Router
}

func NewDiscoveryOrchestrator(
	ctx context.Context,
	localID string,
	ps *peerstore.PeerStore,
	cm transport.ConnectionManager,
	dc discovery.DiscoveryClient,
	router Router,
) *DiscoveryOrchestrator {
	return &DiscoveryOrchestrator{
		ctx:           ctx,
		localID:       localID,
		peerStore:     ps,
		connManager:   cm,
		discoveryCli:  dc,
		connectorTick: 10 * time.Second,
		router:        router,
	}
}

// Run запускает acceptLoop и connectorLoop
func (o *DiscoveryOrchestrator) Run() {
	go o.acceptLoop()
	go o.connectorLoop()
}

// HandleConnection – публичный метод для передачи нового соединения (из bootstrap)
func (o *DiscoveryOrchestrator) HandleConnection(wconn transport.WrappedConnection, isIncoming bool) {
	go o.handleNewConnection(wconn, isIncoming)
}

// acceptLoop – принимает входящие соединения
func (o *DiscoveryOrchestrator) acceptLoop() {
	for {
		select {
		case <-o.ctx.Done():
			return
		default:
		}
		wconn, err := o.connManager.Accept(o.ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			log.Printf("Accept error: %v", err)
			time.Sleep(1 * time.Second)
			continue
		}
		go o.handleNewConnection(wconn, true)
	}
}

// connectorLoop – периодически подключается к пирам без активного соединения
func (o *DiscoveryOrchestrator) connectorLoop() {
	ticker := time.NewTicker(o.connectorTick)
	defer ticker.Stop()
	for {
		select {
		case <-o.ctx.Done():
			return
		case <-ticker.C:
			peers := o.peerStore.List()
			for _, p := range peers {
				if p.Id == o.localID {
					continue
				}
				if !p.Connected() && p.Address != "" {
					go o.tryConnect(p)
				}
			}
		}
	}
}

// tryConnect – попытка установить исходящее соединение
func (o *DiscoveryOrchestrator) tryConnect(p *peerstore.PeerInfo) {
	ctx, cancel := context.WithTimeout(o.ctx, 10*time.Second)
	defer cancel()
	wconn, err := o.connManager.Dial(ctx, p.Address)
	if err != nil {
		log.Printf("Dial to %s (%s) failed: %v", p.Id, p.Address, err)
		return
	}
	o.HandleConnection(wconn, false)
}

// handleNewConnection – обрабатывает новое соединение (входящее или исходящее)
func (o *DiscoveryOrchestrator) handleNewConnection(wconn transport.WrappedConnection, isIncoming bool) {
	peerID := wconn.ID()
	if peerID == o.localID {
		wconn.Close()
		log.Printf("Self-connection, closing")
		return
	}

	// Разрешение коллизий
	if existing, ok := o.peerStore.Get(peerID); ok && existing.Connected() {
		if o.localID < peerID {
			// Мы выигрываем – заменяем соединение
			existing.Connection.Close()
			log.Printf("Collision: keeping new connection to %s (local %s < remote %s)", peerID, o.localID, peerID)
		} else {
			// Мы проигрываем – закрываем новое
			wconn.Close()
			log.Printf("Collision: rejecting new connection to %s, keeping existing", peerID)
			return
		}
	}

	// Создаём контекст для этого соединения
	connCtx, cancel := context.WithCancel(o.ctx)

	// Обновляем PeerStore с новым соединением
	now := time.Now()
	o.peerStore.InsertMerge(&peerstore.PeerInfo{
		Id:         peerID,
		Address:    wconn.RemoteAddr().String(),
		LastSeen:   now,
		Connection: wconn,
	})

	// Запускаем обработку датаграмм
	go o.runDatagramReader(connCtx, wconn, cancel)

	// Запускаем подписку на события удалённого пира
	go o.runDiscoverySubscription(connCtx, wconn, peerID)

	// По завершению контекста помечаем пира как отключённого
	go func() {
		<-connCtx.Done()
		o.peerStore.SetDisconnected(peerID)
	}()
}

// runDatagramReader – читает датаграммы из соединения
func (o *DiscoveryOrchestrator) runDatagramReader(ctx context.Context, wconn transport.WrappedConnection, cancel context.CancelFunc) {
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		data, err := wconn.ReceiveDatagram(ctx)
		if err != nil {
			// Если ошибка не отмена контекста, логируем
			if !errors.Is(err, context.Canceled) {
				log.Printf("ReceiveDatagram error from %s: %v", wconn.ID(), err)
			}
			return
		}

		packet, err := o.router.NewMessageCopyFrom(data)
		if err != nil {
			log.Printf("failed to create message from data: %v", err)
			continue
		}

		o.router.HandleMeshPacket(packet)
	}
}

// runDiscoverySubscription – подписывается на события удалённого пира
func (o *DiscoveryOrchestrator) runDiscoverySubscription(ctx context.Context, wconn transport.WrappedConnection, peerID string) {
	eventCh, err := o.discoveryCli.Subscribe(ctx, wconn.GrpcClient())
	if err != nil {
		log.Printf("Failed to start subscription to %s: %v", peerID, err)
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-eventCh:
			if !ok {
				return
			}
			o.handlePeerEvent(ev, peerID)
		}
	}
}

// handlePeerEvent – применяет событие к PeerStore
func (o *DiscoveryOrchestrator) handlePeerEvent(ev *proto.PeerEvent, fromPeer string) {
	switch ev.Type {
	case proto.PeerEventType_PEER_EVENT_SYNC:
		for _, p := range ev.Dump {
			if p.Id == o.localID || p.Id == fromPeer {
				continue
			}
			o.peerStore.InsertMerge(&peerstore.PeerInfo{
				Id:       p.Id,
				Address:  p.Addr,
				LastSeen: time.Unix(0, p.LastSeen),
			})
		}
	case proto.PeerEventType_PEER_EVENT_JOINED, proto.PeerEventType_PEER_EVENT_UPDATED:
		if ev.Update.Id == o.localID || ev.Update.Id == fromPeer {
			return
		}
		o.peerStore.InsertMerge(&peerstore.PeerInfo{
			Id:       ev.Update.Id,
			Address:  ev.Update.Addr,
			LastSeen: time.Unix(0, ev.Update.LastSeen),
		})
	case proto.PeerEventType_PEER_EVENT_LEFT:
		if ev.Update.Id == o.localID || ev.Update.Id == fromPeer {
			return
		}
		o.peerStore.Remove(ev.Update.Id)
	}
}
