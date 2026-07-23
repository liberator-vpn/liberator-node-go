package router

import (
	"context"
	"fmt"
	"log"
	"math"
	"runtime"
	"sync"
	"time"

	"github.com/TexHik620953/liberator-node-go/internal/appconfig"
	"github.com/TexHik620953/liberator-node-go/internal/utils/dgmessage"
	"github.com/TexHik620953/liberator-node-go/internal/utils/netutils"
	"github.com/TexHik620953/liberator-node-go/pkg/firewall"
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
}

func New(
	ctx context.Context,
	cfg appconfig.RouterConfig,
	routingTable routingtable.RoutingTable,
	firewall firewall.FirewallEngine,
) (*Router, error) {

	gatewayAddr, network, err := netutils.NewNativeIPNet(cfg.CIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	_, globalNetwork, err := netutils.NewNativeIPNet(cfg.GlobalCIRD)
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

		routingTable: routingTable,
		firewall:     firewall,
		toIface:      make(chan *dgmessage.DatagramMessage, 1000),

		gatewayAddr:   gatewayAddr,
		network:       network,
		globalNetwork: globalNetwork,

		shardedWorkers: workers,
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

	if packet.HoleInfo.DstIP == r.gatewayAddr || !r.globalNetwork.Contains(packet.HoleInfo.DstIP) {
		r.toIface <- packet // TUN
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
