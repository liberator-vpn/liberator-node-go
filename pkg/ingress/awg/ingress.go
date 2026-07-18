package awg

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"liberator-node-go/internal/utils/ipalloc"
	"liberator-node-go/internal/utils/routingtable"
	"liberator-node-go/internal/utils/safemap"
	"liberator-node-go/pkg/ingress"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	amneziawgdevice "github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/google/uuid"
)

// ---------------------------------------------------------
// 3. Ингресс
// ---------------------------------------------------------
var _ ingress.Ingress = (*Ingress)(nil)

type Ingress struct {
	ctx context.Context
	cfg *IngressConfig

	packetsPool  routingtable.DGMessagePool
	routingTable routingtable.RoutingTable
	ipAlloc      *ipalloc.IPAllocator
	nodeID       string

	awgDevice  *amneziawgdevice.Device
	channelTun *ChannelTun
	in         chan []byte

	peersById    safemap.Safemap[string, *AWGPeer]
	userIdToPeer safemap.Safemap[string, *AWGPeer] // userID.String() -> Peer

	peerTimeout time.Duration
}

func New(
	ctx context.Context,
	cfg *IngressConfig,
	packetsPool routingtable.DGMessagePool,
	routingTable routingtable.RoutingTable,
	ipAlloc *ipalloc.IPAllocator,
	fromIng chan *routingtable.DatagramMessage, // В AWG мы вынуждены передавать канал в New, т.к. ядро стартует сразу
	nodeID string,
) (*Ingress, error) {
	ig := &Ingress{
		ctx:          ctx,
		cfg:          cfg,
		packetsPool:  packetsPool,
		routingTable: routingTable,
		ipAlloc:      ipAlloc,
		nodeID:       nodeID,
		in:           make(chan []byte, 1000),
		peersById:    safemap.New[string, *AWGPeer](),
		userIdToPeer: safemap.New[string, *AWGPeer](),
		peerTimeout:  3 * time.Minute, // Если нет пакетов 3 минуты - пир мертв
	}

	ig.channelTun = NewChannelTun(ctx, fromIng, ig.in, ig.packetsPool, cfg.MTU)

	udpBind := conn.NewDefaultBind()

	logger := amneziawgdevice.NewLogger(amneziawgdevice.LogLevelVerbose, fmt.Sprintf("(%s-awg) ", nodeID))
	ig.awgDevice = amneziawgdevice.NewDevice(ig.channelTun, udpBind, logger)

	_, portStr, err := net.SplitHostPort(cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid listen address format '%s': %w", cfg.ListenAddr, err)
	}

	if err := ig.awgDevice.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%s\n",
		cfg.PrivateKey,
		portStr,
	)); err != nil {
		return nil, fmt.Errorf("failed to set base AWG config: %w", err)
	}

	if cfg.H1 != "" {
		if err := ig.awgDevice.IpcSet(fmt.Sprintf(
			"h1=%s\nh2=%s\nh3=%s\nh4=%s\njc=%d\njmin=%d\njmax=%d\ns1=%d\ns2=%d\n",
			cfg.H1,
			cfg.H2,
			cfg.H3,
			cfg.H4,
			cfg.Jc,
			cfg.JMin,
			cfg.JMax,
			cfg.S1,
			cfg.S2,
		)); err != nil {
			return nil, fmt.Errorf("failed to set AWG obfuscation config: %w", err)
		}
	}

	if err := ig.awgDevice.Up(); err != nil {
		return nil, fmt.Errorf("failed to bring up AWG device: %w", err)
	}

	log.Printf("[%s] AmneziaWG Ingress started on port %s", nodeID, cfg.ListenAddr)
	return ig, nil
}

// Run запускает фоновый процесс очистки мертвых пиров (аналог defer в QUIC)
func (ig *Ingress) Run() {
	// fromIng игнорируется, так как он уже привязан к TUN адаптеру в New()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ig.ctx.Done():
			log.Printf("[%s] Shutting down AWG Ingress...", ig.nodeID)
			ig.awgDevice.Close()
			close(ig.in)
			return
		case <-ticker.C:
			ig.cleanupDeadPeers()
		}
	}
}

// PreparePeer вызывается из VpnAuthService ДО подключения клиента.
// Добавляет ключ в ядро AWG и выделяет маршрутизируемый объект.
func (ig *Ingress) PreparePeer(userID uuid.UUID, publicKeyHex string) (net.IP, error) {
	// Если юзер уже подключен, удаляем его старую сессию
	ig.KickUser(ig.ctx, userID.String())

	ipNet, err := ig.ipAlloc.Get()
	if err != nil {
		return nil, fmt.Errorf("failed to allocate IP: %w", err)
	}

	peer := NewAWGPeer(ig.nodeID, userID, ipNet, publicKeyHex, ig)

	// Добавляем в ядро AWG
	peerCmd := fmt.Sprintf("public_key=%s\nallowed_ip=%s/32\n", publicKeyHex, ipNet.String())

	if err := ig.awgDevice.IpcSet(peerCmd); err != nil {
		ig.ipAlloc.Free(ipNet)
		return nil, fmt.Errorf("failed to add AWG peer to kernel: %w", err)
	}

	// Добавляем в наши карты и в таблицу маршрутизации
	ig.peersById.Set(peer.id, peer)
	ig.userIdToPeer.Set(userID.String(), peer)

	addr, ok := netip.AddrFromSlice(peer.virtualIP)
	if !ok {
		return nil, fmt.Errorf("invalid virtual ip")
	}

	ig.channelTun.peers.Set(addr, peer)

	if err := ig.routingTable.Add(peer); err != nil {
		// Если не смогли добавить в роутинг, откатываем всё
		ig.removePeerInternal(peer)
		return nil, fmt.Errorf("failed to add peer to routing table: %w", err)
	}

	log.Printf("AWG: Prepared peer %s (User: %s, IP: %s)", publicKeyHex[:8], userID, ipNet.String())
	return ipNet, nil
}

// KickUser реализует интерфейс для IngressManager
func (ig *Ingress) KickUser(ctx context.Context, userID string) bool {
	peer, exists := ig.userIdToPeer.Get(userID)
	if !exists {
		return false
	}
	ig.removePeerInternal(peer)
	return true
}

// removePeerInternal ЭКВИВАЛЕНТ DEFER ИЗ QUIC ИНГРЕССА
// Вызывается при таймауте (Watchdog) или принудительном кике.
func (ig *Ingress) removePeerInternal(peer *AWGPeer) {
	// 1. Удаляем из таблицы маршрутизации
	ig.routingTable.Delete(peer)

	// 2. Освобождаем IP
	if peer.virtualIP != nil {
		ig.ipAlloc.Free(peer.virtualIP)
	}

	// 3. Чистим свои карты
	ig.peersById.Delete(peer.id)
	ig.userIdToPeer.Delete(peer.userID.String())
	if peer.virtualIP != nil {
		addr, ok := netip.AddrFromSlice(peer.virtualIP)
		if ok {
			ig.channelTun.peers.Delete(addr)
		}
	}

	// 4. Удаляем из ядра AmneziaWG
	removeCmd := fmt.Sprintf("public_key=%s\nremove=true\n", peer.pubKey)
	_ = ig.awgDevice.IpcSet(removeCmd)

	log.Printf("AWG: Removed peer User: %s, Released IP: %s", peer.userID, peer.virtualIP)
}

// cleanupDeadPeers Watchdog (Сторожевой таймер)
func (ig *Ingress) cleanupDeadPeers() {
	now := time.Now()
	var toDelete []*AWGPeer

	ig.peersById.Foreach(func(_ string, peer *AWGPeer) {
		if now.Sub(peer.lastSeen) > ig.peerTimeout {
			toDelete = append(toDelete, peer)
		}
	})

	for _, peer := range toDelete {
		log.Printf("AWG: Peer %s timed out (no packets for %v)", peer.userID, ig.peerTimeout)
		ig.removePeerInternal(peer)
	}
}

// writePacket вызывается абстракцией AWGPeer.SendDatagram для отправки данных клиенту
func (ig *Ingress) writePacket(data []byte) error {
	select {
	case ig.in <- data:
		return nil
	case <-ig.ctx.Done():
		return fmt.Errorf("ingress is closed")
	}
}
