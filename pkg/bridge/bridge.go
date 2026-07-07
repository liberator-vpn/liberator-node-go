package bridge

import (
	"context"
	"fmt"
	"liberator-node-go/internal/appconfig"
	"liberator-node-go/internal/utils/cert"
	"liberator-node-go/internal/utils/ipalloc"
	"liberator-node-go/internal/utils/liberatorjwt"
	"liberator-node-go/internal/utils/routingtable"
	"liberator-node-go/internal/utils/safemap"
	"liberator-node-go/pkg/egress"
	"liberator-node-go/pkg/ingress"
	"liberator-node-go/pkg/mesh"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Bridge struct {
	ctx          context.Context
	ipAlloc      *ipalloc.IPAllocator
	routingTable routingtable.RoutingTable

	egr       *egress.Egress
	ingresses safemap.Safemap[string, *ingress.Ingress]
	mesh      *mesh.MeshNode
}

func New(ctx context.Context, cfg appconfig.BridgeConfig, jwtIss *liberatorjwt.LiberatorJWT) (*Bridge, error) {
	br := &Bridge{
		ctx:          ctx,
		ingresses:    safemap.New[string, *ingress.Ingress](),
		routingTable: routingtable.New(),
	}

	var err error
	br.ipAlloc, err = ipalloc.New(cfg.CIDR)
	if err != nil {
		return nil, err
	}

	br.egr, err = egress.New(ctx, cfg.Egress.IfaceInName, cfg.CIDR, cfg.Egress.IfaceOutName, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("failed to create egress: %w", err)
	}

	// Build ingresses
	for name, iconf := range cfg.Ingresses {
		ingressCert, err := cert.ReadCertificateFromFile(iconf.Cert)
		if err != nil {
			return nil, fmt.Errorf("failed to load ingress %s cert: %v", name, err)
		}
		ingressKey, err := cert.ReadPrivateKeyFromFile(iconf.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to load ingress %s key: %v", name, err)
		}

		ing, err := ingress.New(ctx, br.routingTable, br.ipAlloc, iconf.ListenAddr, jwtIss, cert.X509ToTLSCertificate(ingressCert, ingressKey))
		if err != nil {
			return nil, fmt.Errorf("failed to create ingress %s: %w", name, err)
		}
		br.ingresses.Set(name, ing)
	}
	return br, nil
}

func (b *Bridge) Run() {
	ing2bridge := make(chan *ingress.DatagramMessage, 10)
	b.ingresses.Foreach(func(s string, i *ingress.Ingress) {
		go i.Run(ing2bridge)
	})

	bridge2egr, egr2bridge := b.egr.Run()

	// Egress to ingress
	go func() {
		for {
			select {
			case <-b.ctx.Done():
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
				// Extract ip
				packet := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.DecodeOptions{
					Lazy:   true,
					NoCopy: true,
				})
				ipv4Layer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
				if ipv4Layer == nil {
					continue
				}
				targetIP := ipv4Layer.DstIP

				target, ex := b.routingTable.GetByVirtualIp(targetIP)
				if !ex {
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
		case <-b.ctx.Done():
			return
		case dg := <-ing2bridge:
			bridge2egr <- dg.Data
		}
	}

}
