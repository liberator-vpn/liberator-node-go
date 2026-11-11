package awg

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/liberator-vpn/liberator-node-go/internal/metrics"
	"github.com/liberator-vpn/liberator-node-go/internal/utils/netutils"
	"github.com/liberator-vpn/liberator-node-go/internal/utils/safemap"
	"github.com/liberator-vpn/liberator-node-go/pkg/model"
	"github.com/liberator-vpn/liberator-node-go/pkg/routingtable"
	"github.com/liberator-vpn/liberator-node-go/pkg/transport"

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

// ServerPublicKey возвращает публичный ключ сервера из HEX приватного (для клиента).
func ServerPublicKey(privKeyHex string) (string, error) {
	return getServerPubKey(privKeyHex)
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
	closeOnce sync.Once
}

func (ig *AWGTransport) Type() string {
	return "awg"
}

func (ig *AWGTransport) Protocols() []string {
	return []string{"awg"}
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

	logger := amneziawgdevice.NewLogger(amneziawgdevice.LogLevelError, fmt.Sprintf("(%s-awg) ", nodeID))
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
		return nil, fmt.Errorf("failed to set AWG H[1-4] and S[1-4] obfuscation config: %w", err)
	}

	// I1..I5 — опциональные junk/signature-пакеты (AmneziaWG 1.5+/2.0).
	// Без них DPI видит характерный первый пакет рукопожатия.
	for key, val := range map[string]string{
		"i1": cfg.I1, "i2": cfg.I2, "i3": cfg.I3, "i4": cfg.I4, "i5": cfg.I5,
	} {
		if val == "" {
			continue
		}
		if err := ig.awgDevice.IpcSet(fmt.Sprintf("%s=%s\n", key, val)); err != nil {
			return nil, fmt.Errorf("failed to set AWG %s obfuscation config: %w", key, err)
		}
	}

	if cfg.Jc > 0 {
		if err := ig.awgDevice.IpcSet(fmt.Sprintf("jc=%d\n", cfg.Jc)); err != nil {
			return nil, fmt.Errorf("failed to set AWG jc obfuscation config: %w", err)
		}
	}

	if cfg.JMin > 0 {
		if err := ig.awgDevice.IpcSet(fmt.Sprintf("jmin=%d\n", cfg.JMin)); err != nil {
			return nil, fmt.Errorf("failed to set AWG jmin obfuscation config: %w", err)
		}
	}
	if cfg.JMax > 0 {
		if err := ig.awgDevice.IpcSet(fmt.Sprintf("jmax=%d\n", cfg.JMax)); err != nil {
			return nil, fmt.Errorf("failed to set AWG jmax obfuscation config: %w", err)
		}
	}

	if err := ig.awgDevice.Up(); err != nil {
		return nil, fmt.Errorf("failed to bring up AWG device: %w", err)
	}

	log.Printf("[%s] AmneziaWG Transport started on port %d", nodeID, cfg.ListenPort)
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
			log.Printf("[%s] Shutting down AWG Transport...", ig.nodeID)
			ig.Close()
			return
		case <-ticker.C:
			ig.watchPeers()
		}
	}
}

func (ig *AWGTransport) DeltaChan() chan transport.TransportPeerStats {
	return ig.deltaChan
}

// Close идемпотентно останавливает устройство. Нужен для аварийного
// завершения app.New, когда Run ещё не успел запуститься.
func (ig *AWGTransport) Close() {
	ig.closeOnce.Do(func() {
		ig.channelTun.Close()
		ig.awgDevice.Close()
	})
}

// CreatePeer приводит пира к желаемому состоянию. Вызывается реконсилятором
// каждые несколько секунд, поэтому обязан быть идемпотентным: если пир с тем же
// virtual IP и тем же публичным ключом уже поднят, сессия НЕ пересоздаётся
// (иначе у клиента рвётся handshake и обнуляются счётчики каждые 5 секунд).
func (ig *AWGTransport) CreatePeer(peerInfo *model.Peer) error {
	if existing, ok := ig.peersByIP.Get(peerInfo.VirtualIP); ok {
		if existing.pubKey == peerInfo.AwgPublicKey {
			// Пир уже есть: обновляем только лимиты, если маршрут шейпится.
			if shaped, isShaped := ig.router.GetRemoteRoutingObject(peerInfo.VirtualIP); isShaped {
				if sr, ok := shaped.(*routingtable.ShapedRoute); ok {
					speed, traffic := limitsOf(peerInfo)
					if sr.SetLimits(speed, traffic) {
						return nil
					}
				}
			}
			if peerInfo.SpeedLimitMbps == nil && peerInfo.TrafficLimitGb == nil {
				return nil
			}
			// Режим лимитирования изменился — пересоздаём ниже.
		}
		// Тот же IP, но другой ключ (клиент перегенерировал keypair) либо
		// изменился режим лимитов — снимаем старую сессию.
		ig.KickPeer(peerInfo.VirtualIP)
	}

	var peer routingtable.RoutingObject
	awgPeer := NewAWGPeer(ig.ctx, ig.nodeID, peerInfo.VirtualIP, peerInfo.AwgPublicKey, ig, peerInfo.ExpirationDate)
	peer = awgPeer
	// Wrap this to shaped object
	if peerInfo.SpeedLimitMbps != nil || peerInfo.TrafficLimitGb != nil {
		speedLimit, trafficLimit := limitsOf(peerInfo)
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

	if err := ig.router.AddRoutingObject(peer); err != nil {
		// Если не смогли добавить в роутинг, откатываем всё
		ig.removePeerInternal(awgPeer)
		return fmt.Errorf("failed to add peer to routing table: %w", err)
	}

	return nil
}

// limitsOf переводит лимиты из model.Peer в байты/байт-в-секунду.
func limitsOf(peerInfo *model.Peer) (speed *uint64, traffic *uint64) {
	if peerInfo.SpeedLimitMbps != nil {
		v := uint64((*peerInfo.SpeedLimitMbps) * 1024 * 1024)
		speed = &v
	}
	if peerInfo.TrafficLimitGb != nil {
		total := *peerInfo.TrafficLimitGb * 1024 * 1024 * 1024
		used := float64(peerInfo.FromPeerTotal + peerInfo.ToPeerTotal)
		if remaining := total - used; remaining > 0 {
			v := uint64(remaining)
			traffic = &v
		} else {
			v := uint64(0)
			traffic = &v
		}
	}
	return speed, traffic
}

func (ig *AWGTransport) ExistsPeer(ip uint32) bool {
	return ig.peersByIP.Exists(ip)
}

// KickPeer реализует интерфейс для Transport
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
			if now.After(*peer.expiration) {
				toDelete = append(toDelete, peer)
			}
		}
		toPeer, fromPeer, lastSeen := peer.snapshotStats()
		select {
		case ig.deltaChan <- transport.TransportPeerStats{
			VirtualIP:     peer.virtualIP,
			LastSeen:      lastSeen,
			DeltaToPeer:   toPeer,
			DeltaFromPeer: fromPeer,
		}:
		default:
			// Канал дельт переполнен: возвращаем срез пиру, чтобы он ушёл
			// на следующем тике, а не потерялся (раньше Swap(0) выполнялся
			// даже при выборе default и байты исчезали из биллинга).
			peer.totalToPeer.Add(toPeer)
			peer.totalFromPeer.Add(fromPeer)
		}
	})

	for _, peer := range toDelete {
		ig.removePeerInternal(peer)
	}
}

// writePacket вызывается абстракцией AWGPeer.SendDatagram для отправки данных клиенту
func (ig *AWGTransport) writePacket(data []byte) error {
	metrics.ObserveTraffic(metrics.DirOut, metrics.PeerClient, Protocol, len(data))
	select {
	case ig.in <- data:
		return nil
	case <-ig.ctx.Done():
		return fmt.Errorf("transport is closed")
	}
}
