package bridge

import (
	"context"
	"crypto/tls"
	"fmt"
	"liberator-node-go/internal/appconfig"
	"liberator-node-go/internal/infra/repos"
	"liberator-node-go/internal/utils/ipalloc"
	"liberator-node-go/internal/utils/liberatorjwt"
	"liberator-node-go/internal/utils/routingtable"
	"liberator-node-go/internal/utils/safemap"
	"liberator-node-go/pkg/egress"
	"liberator-node-go/pkg/ingress"
	"liberator-node-go/pkg/mesh"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Bridge struct {
	ctx          context.Context
	ipAlloc      *ipalloc.IPAllocator
	routingTable routingtable.RoutingTable

	egr       *egress.Egress
	ingresses safemap.Safemap[string, *ingress.Ingress]
	meshNode  *mesh.MeshNode

	dbPool *repos.DbPool

	gatewayAddr   net.IP
	network       *net.IPNet
	globalNetwork *net.IPNet
}

func New(
	ctx context.Context,
	cfg appconfig.BridgeConfig,
	jwtIss *liberatorjwt.LiberatorJWT,
	meshNode *mesh.MeshNode,
	dbPool *repos.DbPool,
	routingTable routingtable.RoutingTable,
) (*Bridge, error) {
	br := &Bridge{
		ctx:          ctx,
		ingresses:    safemap.New[string, *ingress.Ingress](),
		routingTable: routingTable,
		meshNode:     meshNode,
		dbPool:       dbPool,
	}

	var err error
	br.egr, err = egress.New(ctx, cfg.Egress.IfaceInName, cfg.CIDR, cfg.Egress.IfaceOutName, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("failed to create egress: %w", err)
	}

	_, br.globalNetwork, err = net.ParseCIDR(cfg.GlobalCIRD)
	if err != nil {
		return nil, fmt.Errorf("invalid global CIDR: %v", err)
	}

	// Build ip allocator and reserve gateway address
	br.ipAlloc, err = ipalloc.New(cfg.CIDR)
	if err != nil {
		return nil, err
	}
	br.gatewayAddr, br.network, err = net.ParseCIDR(cfg.CIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}
	err = br.ipAlloc.Reserve(br.gatewayAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to reserve ip for gateway: %v", err)
	}

	// Build ingresses
	for name, iconf := range cfg.Ingresses {
		certificate, err := tls.LoadX509KeyPair(iconf.Cert, iconf.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to load cert key pair: %v", err)
		}

		ing, err := ingress.New(ctx, br.routingTable, br.ipAlloc, iconf.ListenAddr, jwtIss, &certificate, br.dbPool, cfg.DNS, cfg.MTU, meshNode.NodeID())
		if err != nil {
			return nil, fmt.Errorf("failed to create ingress %s: %w", name, err)
		}
		br.ingresses.Set(name, ing)
	}
	return br, nil
}

func (br *Bridge) handleTUNPacket(data []byte) {
	if len(data) == 0 {
		return
	}
	version := data[0] >> 4
	if version == 6 {
		// Ip v6 not supported
		return
	}
	// Extract ip to identify target ip.
	packet := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.DecodeOptions{
		Lazy:   true,
		NoCopy: true,
	})
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ipv4Layer == nil {
		return
	}

	target, ex := br.routingTable.GetByVirtualIp(ipv4Layer.DstIP)
	if !ex {
		// TODO: Probably packet for internet
		return
	}
	err := target.SendDatagram(data)
	if err != nil {
		log.Printf("failed to send datagram %d: %v", len(data), err)
	}
}
func (br *Bridge) handleMeshPacket(data []byte) {
	if len(data) == 0 {
		return
	}
	version := data[0] >> 4
	if version == 6 {
		// Ip v6 not supported
		return
	}
	// Extract ip to identify target ip.
	packet := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.DecodeOptions{
		Lazy:   true,
		NoCopy: true,
	})
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer == nil {
		return
	}
	ip := ipv4Layer.(*layers.IPv4)

	// Извлекаем информацию для Holepunch
	var srcPort, dstPort uint16
	var protocolStr string
	switch ip.Protocol {
	case layers.IPProtocolTCP:
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)
			srcPort = uint16(tcp.SrcPort)
			dstPort = uint16(tcp.DstPort)
			protocolStr = "tcp"
		}
	case layers.IPProtocolUDP:
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp := udpLayer.(*layers.UDP)
			srcPort = uint16(udp.SrcPort)
			dstPort = uint16(udp.DstPort)
			protocolStr = "udp"
		}
	case layers.IPProtocolICMPv4:
		protocolStr = "icmp"
		// порты не используются
	default:
		// Другие протоколы игнорируем (не создаём дырку)
	}

	// Создаём дырку для этого потока, чтобы ответы проходили без проверки правил
	if protocolStr != "" {
		hi := routingtable.HoleInfo{
			SrcIP:    ip.SrcIP,
			DstIP:    ip.DstIP,
			SrcPort:  srcPort,
			DstPort:  dstPort,
			Protocol: protocolStr,
		}
		br.routingTable.Holepunch(hi, time.Minute)
	}

	target, ex := br.routingTable.GetByVirtualIp(ip.DstIP)
	if !ex {
		// TODO: Probably packet for internet
		return
	}
	err := target.SendDatagram(data)
	if err != nil {
		log.Printf("failed to send datagram %d: %v", len(data), err)
	}
}
func (br *Bridge) Run() {

	mesh2bridge := br.meshNode.DatagramChan()

	ing2bridge := make(chan *routingtable.DatagramMessage, 500)
	br.ingresses.Foreach(func(s string, i *ingress.Ingress) {
		go i.Run(ing2bridge)
	})

	bridge2egr, egr2bridge := br.egr.Run()

	var wg sync.WaitGroup

	for range 5 {
		wg.Go(func() {
			for {
				select {
				case <-br.ctx.Done():
					return
				case data := <-egr2bridge:
					br.handleTUNPacket(data)
				case data := <-mesh2bridge:
					br.handleMeshPacket(data)
				}
			}
		})
	}
	for range 5 {
		wg.Go(func() {
			for {
				select {
				case <-br.ctx.Done():
					return
				case dg := <-ing2bridge:
					if dg.HoleInfo.DstIP.Equal(br.gatewayAddr) || !br.globalNetwork.Contains(dg.HoleInfo.DstIP) {
						bridge2egr <- dg.Data // TUN
						continue
					}

					hi := routingtable.HoleInfo{
						SrcIP:    dg.HoleInfo.SrcIP,
						DstIP:    dg.HoleInfo.DstIP,
						SrcPort:  dg.HoleInfo.SrcPort,
						DstPort:  dg.HoleInfo.DstPort,
						Protocol: dg.HoleInfo.Protocol,
					}
					if !br.routingTable.RuleCheck(hi) {
						continue
					}
					br.routingTable.Holepunch(hi, time.Minute)

					if br.network.Contains(dg.HoleInfo.DstIP) {
						bridge2egr <- dg.Data // TUN
					} else {
						conn, ex := br.routingTable.GetByVirtualIp(dg.HoleInfo.DstIP)
						if !ex {
							continue
						}
						err := conn.SendDatagram(dg.Data)
						if err != nil {
							fmt.Printf("failed to send datagram to mesh: %v", err)
						}
					}
				}
			}
		})
	}
	wg.Wait()
}
