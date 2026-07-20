package awg

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"liberator-node-go/internal/utils/netutils"
	"liberator-node-go/internal/utils/safemap"
	"liberator-node-go/pkg/model"
	"liberator-node-go/pkg/transport"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	amneziawgdevice "github.com/amnezia-vpn/amneziawg-go/device"
)

var _ transport.Transport = (*AWGTransport)(nil)

type AWGTransport struct {
	ctx context.Context
	cfg *TransportConfig

	router transport.Router
	nodeID string

	awgDevice  *amneziawgdevice.Device
	channelTun *ChannelTun
	in         chan []byte

	peersByIP safemap.Safemap[uint32, *AWGPeer]
}

func New(
	ctx context.Context,
	cfg *TransportConfig,
	router transport.Router,
	nodeID string,
) (*AWGTransport, error) {
	ig := &AWGTransport{
		ctx:       ctx,
		cfg:       cfg,
		router:    router,
		nodeID:    nodeID,
		in:        make(chan []byte, 1000),
		peersByIP: safemap.New[uint32, *AWGPeer](),
	}

	ig.channelTun = NewChannelTun(ctx, ig.in, ig.router, cfg.MTU)

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

	if err := ig.awgDevice.IpcSet(fmt.Sprintf(
		"h1=%s\nh2=%s\nh3=%s\nh4=%s\ns1=%d\ns2=%d\n",
		cfg.H1,
		cfg.H2,
		cfg.H3,
		cfg.H4,
		cfg.S1,
		cfg.S2,
	)); err != nil {
		return nil, fmt.Errorf("failed to set AWG H[1-4] and S[1-2] obfuscation config: %w", err)
	}

	if cfg.Jc > 0 {
		if err := ig.awgDevice.IpcSet(fmt.Sprintf("jc=%d\n", cfg.Jc)); err != nil {
			return nil, fmt.Errorf("failed to set AWG jc obfuscation config: %w", err)
		}
	}

	if cfg.JMin > 0 {
		if err := ig.awgDevice.IpcSet(fmt.Sprintf("jmin=%d\n", cfg.Jc)); err != nil {
			return nil, fmt.Errorf("failed to set AWG jmin obfuscation config: %w", err)
		}
	}
	if cfg.JMax > 0 {
		if err := ig.awgDevice.IpcSet(fmt.Sprintf("jmax=%d\n", cfg.Jc)); err != nil {
			return nil, fmt.Errorf("failed to set AWG jmax obfuscation config: %w", err)
		}
	}

	if err := ig.awgDevice.Up(); err != nil {
		return nil, fmt.Errorf("failed to bring up AWG device: %w", err)
	}

	log.Printf("[%s] AmneziaWG Ingress started on port %s", nodeID, cfg.ListenAddr)
	return ig, nil
}

// Run запускает фоновый процесс очистки мертвых пиров (аналог defer в QUIC)
func (ig *AWGTransport) Run() {
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
func (ig *AWGTransport) PreparePeer(peerInfo *model.Peer) error {
	// Если юзер уже подключен, удаляем его старую сессию
	ig.KickUser(peerInfo.VirtualIP)

	peer := NewAWGPeer(ig.nodeID, peerInfo.VirtualIP, peerInfo.AwgPublicKey, ig, peerInfo.ExpirationDate)

	// Добавляем в ядро AWG
	peerCmd := fmt.Sprintf("public_key=%s\nallowed_ip=%s/32\n", peerInfo.AwgPublicKey, netutils.Uint32ToIPString(peerInfo.VirtualIP))
	if err := ig.awgDevice.IpcSet(peerCmd); err != nil {
		return fmt.Errorf("failed to add AWG peer to kernel: %w", err)
	}

	// Добавляем в наши карты и в таблицу маршрутизации
	ig.peersByIP.Set(peer.virtualIP, peer)

	ig.channelTun.peers.Set(peer.virtualIP, peer)

	if err := ig.router.AddRoutingObject(peer); err != nil {
		// Если не смогли добавить в роутинг, откатываем всё
		ig.removePeerInternal(peer)
		return fmt.Errorf("failed to add peer to routing table: %w", err)
	}

	return nil
}

// KickUser реализует интерфейс для IngressManager
func (ig *AWGTransport) KickUser(userIP uint32) bool {
	peer, exists := ig.peersByIP.Get(userIP)
	if !exists {
		return false
	}
	ig.removePeerInternal(peer)
	return true
}

// removePeerInternal ЭКВИВАЛЕНТ DEFER ИЗ QUIC ИНГРЕССА
// Вызывается при таймауте (Watchdog) или принудительном кике.
func (ig *AWGTransport) removePeerInternal(peer *AWGPeer) {
	// 1. Удаляем из таблицы маршрутизации
	ig.router.DeleteRoutingObject(peer)

	// 3. Чистим свои карты
	ig.peersByIP.Delete(peer.virtualIP)
	ig.channelTun.peers.Delete(peer.virtualIP)

	// 4. Удаляем из ядра AmneziaWG
	removeCmd := fmt.Sprintf("public_key=%s\nremove=true\n", peer.pubKey)
	_ = ig.awgDevice.IpcSet(removeCmd)

}

// cleanupDeadPeers Watchdog (Сторожевой таймер)
func (ig *AWGTransport) cleanupDeadPeers() {
	now := time.Now()
	var toDelete []*AWGPeer

	ig.peersByIP.Foreach(func(_ uint32, peer *AWGPeer) {
		if peer.expiration != nil {
			if peer.expiration.After(now) {
				toDelete = append(toDelete, peer)
			}
		}
	})

	for _, peer := range toDelete {
		ig.removePeerInternal(peer)
	}
}

// writePacket вызывается абстракцией AWGPeer.SendDatagram для отправки данных клиенту
func (ig *AWGTransport) writePacket(data []byte) error {
	select {
	case ig.in <- data:
		return nil
	case <-ig.ctx.Done():
		return fmt.Errorf("ingress is closed")
	}
}
