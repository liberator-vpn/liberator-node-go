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

	gatewayAddr net.IP
	network     *net.IPNet
}

func New(
	ctx context.Context,
	cfg appconfig.BridgeConfig,
	jwtIss *liberatorjwt.LiberatorJWT,
	meshNode *mesh.MeshNode,
	dbPool *repos.DbPool,
) (*Bridge, error) {
	br := &Bridge{
		ctx:          ctx,
		ingresses:    safemap.New[string, *ingress.Ingress](),
		routingTable: routingtable.New(),
		meshNode:     meshNode,
		dbPool:       dbPool,
	}

	var err error
	br.egr, err = egress.New(ctx, cfg.Egress.IfaceInName, cfg.CIDR, cfg.Egress.IfaceOutName, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("failed to create egress: %w", err)
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
	// Launch dns server

	// Build ingresses
	for name, iconf := range cfg.Ingresses {
		certificate, err := tls.LoadX509KeyPair(iconf.Cert, iconf.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to load cert key pair: %v", err)
		}

		ing, err := ingress.New(ctx, br.routingTable, br.ipAlloc, iconf.ListenAddr, jwtIss, &certificate, br.dbPool)
		if err != nil {
			return nil, fmt.Errorf("failed to create ingress %s: %w", name, err)
		}
		br.ingresses.Set(name, ing)
	}
	return br, nil
}

func (br *Bridge) Run() {
	ing2bridge := make(chan *ingress.DatagramMessage, 10)
	br.ingresses.Foreach(func(s string, i *ingress.Ingress) {
		go i.Run(ing2bridge)
	})

	bridge2egr, egr2bridge := br.egr.Run()

	// Egress to ingress
	go func() {
		for {
			select {
			case <-br.ctx.Done():
				return
			case data := <-egr2bridge:
				if len(data) == 0 {
					continue
				}
				version := data[0] >> 4
				if version == 6 {
					// Ip v6 not supported
					continue
				}
				// Extract ip to identify target ip.
				packet := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.DecodeOptions{
					Lazy:   true,
					NoCopy: true,
				})
				ipv4Layer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
				if ipv4Layer == nil {
					continue
				}
				targetIP := ipv4Layer.DstIP

				target, ex := br.routingTable.GetByVirtualIp(targetIP)
				if !ex {
					// TODO: Here we should check mesh routing table and pass there
					continue
				}
				err := target.SendDatagram(data)
				if err != nil {
					log.Printf("failed to send datagram %d: %v", len(data), err)
				}

			}
		}
	}()

	for {
		select {
		case <-br.ctx.Done():
			return
		case dg := <-ing2bridge:
			if br.network.Contains(dg.DstIP) && !dg.DstIP.Equal(br.gatewayAddr) {
				// Ip addr is in our network but not gateway.
				if !br.routingTable.IsAllowedIps(dg.SrcIP, dg.DstIP) {
					continue
				}
			}
			bridge2egr <- dg.Data
		}
	}

}
