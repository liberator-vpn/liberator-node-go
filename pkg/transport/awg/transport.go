package awg

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/TexHik620953/liberator-node-go/internal/utils/netutils"
	"github.com/TexHik620953/liberator-node-go/internal/utils/safemap"
	"github.com/TexHik620953/liberator-node-go/pkg/model"
	"github.com/TexHik620953/liberator-node-go/pkg/routingtable"
	"github.com/TexHik620953/liberator-node-go/pkg/transport"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	amneziawgdevice "github.com/amnezia-vpn/amneziawg-go/device"
	"golang.org/x/crypto/curve25519"
)

// getServerPubKey из HEX приватного ключа делает HEX публичный
func getServerPubKey(privKeyHex string) (string, error) {
	// Декодируем HEX в 32 байта
	privBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return "", fmt.Errorf("invalid hex private key: %w", err)
	}
	if len(privBytes) != 32 {
		return "", fmt.Errorf("private key must be 32 bytes")
	}
	pubBytes, err := curve25519.X25519(privBytes, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(pubBytes), nil
}

var _ transport.Transport = (*AWGTransport)(nil)

type AWGTransport struct {
	ctx context.Context
	cfg *TransportConfig

	publicKey string

	router transport.Router
	nodeID string

	awgDevice  *amneziawgdevice.Device
	channelTun *ChannelTun
	in         chan []byte

	peersByIP safemap.Safemap[uint32, *AWGPeer]

	deltaChan chan transport.TransportPeerStats
}

func (ig *AWGTransport) Type() string {
	return "awg"
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
		deltaChan: make(chan transport.TransportPeerStats, 100),
	}

	pubKey, err := getServerPubKey(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get pub key: %v", err)
	}
	ig.publicKey = pubKey

	ig.channelTun = NewChannelTun(ctx, ig.in, ig.router, cfg.MTU)

	udpBind := conn.NewDefaultBind()

	logger := amneziawgdevice.NewLogger(amneziawgdevice.LogLevelVerbose, fmt.Sprintf("(%s-awg) ", nodeID))
	ig.awgDevice = amneziawgdevice.NewDevice(ig.channelTun, udpBind, logger)

	if err := ig.awgDevice.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n",
		cfg.PrivateKey,
		cfg.ListenPort,
	)); err != nil {
		return nil, fmt.Errorf("failed to set base AWG config: %w", err)
	}

	if err := ig.awgDevice.IpcSet(fmt.Sprintf(
		"h1=%s\nh2=%s\nh3=%s\nh4=%s\ns1=%d\ns2=%d\ns3=%d\ns4=%d\n",
		cfg.H1,
		cfg.H2,
		cfg.H3,
		cfg.H4,
		cfg.S1,
		cfg.S2,
		cfg.S3,
		cfg.S4,
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

	log.Printf("[%s] AmneziaWG Ingress started on port %d", nodeID, cfg.ListenPort)
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
			fmt.Println("transport exit")
			return
		case <-ticker.C:
			ig.watchPeers()
		}
	}
}

func (ig *AWGTransport) DeltaChan() chan transport.TransportPeerStats {
	return ig.deltaChan
}

// CreatePeer вызывается из VpnAuthService ДО подключения клиента.
// Добавляет ключ в ядро AWG и выделяет маршрутизируемый объект.
func (ig *AWGTransport) CreatePeer(peerInfo *model.Peer) error {
	// Если юзер уже подключен, удаляем его старую сессию
	ig.KickPeer(peerInfo.VirtualIP)

	// TODO: move cretion/deletion to router
	var peer routingtable.RoutingObject
	awgPeer := NewAWGPeer(ig.ctx, ig.nodeID, peerInfo.VirtualIP, peerInfo.AwgPublicKey, ig, peerInfo.ExpirationDate)
	peer = awgPeer
	// Wrap this to shaped object
	if peerInfo.SpeedLimitMbps != nil || peerInfo.TrafficLimitGb != nil {
		var speedLimit *uint64
		var trafficLimit *uint64

		if peerInfo.SpeedLimitMbps != nil {
			v := uint64((*peerInfo.SpeedLimitMbps) * 1024 * 1024)
			speedLimit = &v
		}
		if peerInfo.TrafficLimitGb != nil {
			v := uint64(*peerInfo.TrafficLimitGb*1024*1024*1024) - uint64(peerInfo.FromPeerTotal+peerInfo.ToPeerTotal)
			trafficLimit = &v
		}
		peer = routingtable.NewShapedRoute(peer, speedLimit, trafficLimit)
	}

	// Добавляем в ядро AWG
	peerCmd := fmt.Sprintf("public_key=%s\nallowed_ip=%s/32\n", peerInfo.AwgPublicKey, netutils.Uint32ToIPString(peerInfo.VirtualIP))
	if err := ig.awgDevice.IpcSet(peerCmd); err != nil {
		return fmt.Errorf("failed to add AWG peer to kernel: %w", err)
	}
	// Добавляем в наши карты и в таблицу маршрутизации
	ig.peersByIP.Set(awgPeer.virtualIP, awgPeer)
	ig.channelTun.peers.Set(awgPeer.virtualIP, awgPeer)

	// TODO: move cretion/deletion to router
	if err := ig.router.AddRoutingObject(peer); err != nil {
		// Если не смогли добавить в роутинг, откатываем всё
		ig.removePeerInternal(awgPeer)
		return fmt.Errorf("failed to add peer to routing table: %w", err)
	}

	return nil
}

// KickPeer реализует интерфейс для IngressManager
func (ig *AWGTransport) KickPeer(ip uint32) bool {
	peer, exists := ig.peersByIP.Get(ip)
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
	// TODO: move cretion/deletion to router
	ig.router.DeleteRoutingObject(peer.GetVirtualIP())

	// 3. Чистим свои карты
	ig.peersByIP.Delete(peer.virtualIP)
	ig.channelTun.peers.Delete(peer.virtualIP)

	// 4. Удаляем из ядра AmneziaWG
	removeCmd := fmt.Sprintf("public_key=%s\nremove=true\n", peer.pubKey)
	_ = ig.awgDevice.IpcSet(removeCmd)

}

// watchPeers Watchdog (Сторожевой таймер)
func (ig *AWGTransport) watchPeers() {
	now := time.Now()
	var toDelete []*AWGPeer

	ig.peersByIP.Foreach(func(_ uint32, peer *AWGPeer) {
		if peer.expiration != nil {
			if peer.expiration.After(now) {
				toDelete = append(toDelete, peer)
			}
		}
		select {
		case ig.deltaChan <- transport.TransportPeerStats{
			VirtualIP: peer.virtualIP,
			LastSeen:  peer.lastSeen,

			DeltaToPeer:   peer.totalToPeer.Swap(0),
			DeltaFromPeer: peer.totalFromPeer.Swap(0),
		}:
		default:
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
