package router

import (
	"context"
	"fmt"
	"log"
	"math"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TexHik620953/liberator-node-go/internal/appconfig"
	"github.com/TexHik620953/liberator-node-go/internal/utils/dgmessage"
	"github.com/TexHik620953/liberator-node-go/internal/utils/netutils"
	"github.com/TexHik620953/liberator-node-go/pkg/firewall"
	"github.com/TexHik620953/liberator-node-go/pkg/model"
	"github.com/TexHik620953/liberator-node-go/pkg/routingtable"
)

type Router struct {
	ctx         context.Context
	packetsPool dgmessage.DGMessagePool

	routingTable routingtable.RoutingTable
	firewall     firewall.FirewallEngine

	toIface chan *dgmessage.DatagramMessage

	gatewayAddr   uint32
	network       netutils.NativeIPNet
	globalNetwork netutils.NativeIPNet

	shardedWorkers []chan datagramMessageInfo

	routingsubs   map[chan RouterEvent]struct{}
	routingSubsMu sync.Mutex

	firewallsubs   map[chan FirewallEvent]struct{}
	firewallSubsMu sync.Mutex

	// Stats
	totalFromPeers atomic.Uint64
	totalFromIface atomic.Uint64
	totalFromMesh  atomic.Uint64
}

func New(
	ctx context.Context,
	cfg appconfig.RouterConfig,
	nodeCIDR, globalCIDR string,
) (*Router, error) {

	gatewayAddr, network, err := netutils.NewNativeIPNet(nodeCIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	_, globalNetwork, err := netutils.NewNativeIPNet(globalCIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid global CIDR: %w", err)
	}

	workersNum := runtime.GOMAXPROCS(0)
	workers := make([]chan datagramMessageInfo, workersNum)
	for i := range workers {
		workers[i] = make(chan datagramMessageInfo, 1000)
	}

	br := &Router{
		ctx:         ctx,
		packetsPool: dgmessage.NewDGMessagePool(math.MaxUint16),

		routingTable: routingtable.New(),
		firewall:     firewall.New(),
		toIface:      make(chan *dgmessage.DatagramMessage, 1000),

		gatewayAddr:   gatewayAddr,
		network:       network,
		globalNetwork: globalNetwork,

		shardedWorkers: workers,

		routingsubs:  make(map[chan RouterEvent]struct{}),
		firewallsubs: make(map[chan FirewallEvent]struct{}),
	}
	return br, nil
}

// sudo sysctl -w net.core.default_qdisc=fq                                                                                                                                                                                                             ✔
// sudo sysctl -w net.ipv4.tcp_congestion_control=bbr
func (r *Router) Run() {
	// Launch sharded workers
	var wg sync.WaitGroup

	for _, shardChan := range r.shardedWorkers {
		wg.Go(func() {
			for {
				select {
				case <-r.ctx.Done():
					return
				case packet := <-shardChan:
					switch packet.From {
					case fromTun:
						r.handleTunPacketInternal(packet.Msg)
					case fromMesh:
						r.handleMeshPacketInternal(packet.Msg)
					case fromTransport:
						r.handleTransportPacketInternal(packet.Msg)
					}
				}
			}
		})
	}

	wg.Wait()
}

// Packets handling methods
func (r *Router) handleTunPacketInternal(packet *dgmessage.DatagramMessage) {
	r.totalFromIface.Add(uint64(len(packet.Data)))
	peer, ex := r.routingTable.GetByIP(packet.HoleInfo.DstIP)
	if !ex {
		packet.Free()
		return
	}
	if shaped, ok := peer.(*routingtable.ShapedRoute); ok {
		err := shaped.PushLimited(packet)
		if err != nil {
			log.Printf("failed to push to shaped connection: %v", err)
			packet.Free()
		}
	} else {
		err := peer.SendDatagram(packet.Data)
		if err != nil {
			log.Printf("failed to send datagram from mesh %d: %v", len(packet.Data), err)
		}
		packet.Free()
	}
}
func (r *Router) handleMeshPacketInternal(packet *dgmessage.DatagramMessage) {
	r.totalFromMesh.Add(uint64(len(packet.Data)))
	if packet.HoleInfo.Protocol != "" {
		r.firewall.Holepunch(packet.HoleInfo, time.Minute)
	}

	peer, ex := r.routingTable.GetByIP(packet.HoleInfo.DstIP)
	if !ex {
		packet.Free()
		return
	}

	if shaped, ok := peer.(*routingtable.ShapedRoute); ok {
		err := shaped.PushLimited(packet)
		if err != nil {
			log.Printf("failed to push to shaped connection: %v", err)
			packet.Free()
		}
	} else {
		err := peer.SendDatagram(packet.Data)
		if err != nil {
			log.Printf("failed to send datagram from mesh %d: %v", len(packet.Data), err)
		}
		packet.Free()
	}
}
func (r *Router) handleTransportPacketInternal(packet *dgmessage.DatagramMessage) {
	r.totalFromPeers.Add(uint64(len(packet.Data)))
	srcPeer, ex := r.routingTable.GetByIP(packet.HoleInfo.SrcIP)
	// Check rate limits
	if ex {
		if shaped, ok := srcPeer.(*routingtable.ShapedRoute); ok {
			if !shaped.IsAllowed(uint64(len(packet.Data))) {
				packet.Free()
				return
			}
		}
	}

	if packet.HoleInfo.DstIP == r.gatewayAddr {
		r.toIface <- packet // TUN (локальные сервисы ноды: DNS и т.п.)
		return
	}
	if !r.globalNetwork.Contains(packet.HoleInfo.DstIP) {
		// Выход в интернет. Режем зарезервированные диапазоны, чтобы клиент не мог
		// достучаться до loopback, LAN хостовой машины и облачных metadata-эндпоинтов
		// (169.254.169.254 — кража кредов инстанса).
		if isForbiddenEgress(packet.HoleInfo.DstIP) {
			packet.Free()
			return
		}
		r.toIface <- packet // TUN → интернет через NAT
		return
	}
	hi := dgmessage.HoleInfo{
		SrcIP:    packet.HoleInfo.SrcIP,
		DstIP:    packet.HoleInfo.DstIP,
		SrcPort:  packet.HoleInfo.SrcPort,
		DstPort:  packet.HoleInfo.DstPort,
		Protocol: packet.HoleInfo.Protocol,
	}
	if !r.firewall.RuleCheck(hi) {
		packet.Free()
		return
	}
	r.firewall.Holepunch(hi, time.Minute)

	peer, ex := r.routingTable.GetByIP(packet.HoleInfo.DstIP)
	if !ex {
		packet.Free()
		return
	}
	err := peer.SendDatagram(packet.Data)
	if err != nil {
		log.Printf("failed to send datagram to mesh: %v", err)
	}
	packet.Free()
}

// isForbiddenEgress отсекает адреса, куда VPN-клиент не должен уметь ходить наружу:
// this-network, loopback, link-local (включая облачный metadata 169.254.169.254),
// приватные сети хоста (RFC1918), multicast и reserved. Мешевые адреса сюда не
// попадают — они отсекаются раньше по globalNetwork.Contains.
// ponytail: денйлист захардкожен. Если деплою нужен доступ клиента в LAN — вынести в конфиг.
func isForbiddenEgress(ip uint32) bool {
	switch {
	case ip>>24 == 0x00: // 0.0.0.0/8
		return true
	case ip>>24 == 0x7F: // 127.0.0.0/8 loopback
		return true
	case ip>>24 == 0x0A: // 10.0.0.0/8
		return true
	case ip>>16 == 0xA9FE: // 169.254.0.0/16 link-local + cloud metadata
		return true
	case ip>>16 == 0xC0A8: // 192.168.0.0/16
		return true
	case ip >= 0xAC100000 && ip <= 0xAC1FFFFF: // 172.16.0.0/12
		return true
	case ip >= 0xE0000000: // 224.0.0.0/4 multicast + 240.0.0.0/4 reserved + broadcast
		return true
	default:
		return false
	}
}

func (r *Router) GetStats() model.RouterStats {
	return model.RouterStats{
		TotalFromIface: r.totalFromIface.Load(),
		TotalFromMesh:  r.totalFromMesh.Load(),
		TotalFromPeers: r.totalFromPeers.Load(),
	}
}
