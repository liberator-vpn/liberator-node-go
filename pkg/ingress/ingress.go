package ingress

import (
	"context"
	"crypto/tls"
	"liberator-node-go/internal/utils/ipalloc"
	"liberator-node-go/internal/utils/liberatorjwt"
	"liberator-node-go/internal/utils/safemap"
	"liberator-node-go/pkg/ingress/ingressproto"
	"sync"

	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/quic-go/quic-go"
)

type Ingress struct {
	ctx  context.Context
	cert *tls.Certificate

	udpBind   *net.UDPConn
	transport *quic.Transport
	lis       *quic.Listener

	jwtIss *liberatorjwt.LiberatorJWT

	connections safemap.Safemap[string, *IngressConnection]
	// By virtual ip
	authorizedConnections safemap.Safemap[string, *IngressConnection]

	ipAlloc *ipalloc.IPAllocator

	in, out chan []byte

	runOnce sync.Once
}

func New(ctx context.Context, lisAddr string, jwtIss *liberatorjwt.LiberatorJWT, cert *tls.Certificate) (*Ingress, error) {
	ig := &Ingress{
		ctx:                   ctx,
		cert:                  cert,
		connections:           safemap.New[string, *IngressConnection](),
		authorizedConnections: safemap.New[string, *IngressConnection](),
		jwtIss:                jwtIss,
	}
	var err error

	ig.ipAlloc, err = ipalloc.New("10.8.0.0/16")
	if err != nil {
		return nil, err
	}

	addr, err := net.ResolveUDPAddr("udp", lisAddr)
	if err != nil {
		return nil, err
	}

	ig.udpBind, err = net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	ig.transport = &quic.Transport{
		Conn: ig.udpBind,
	}

	ig.lis, err = ig.transport.Listen(&tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"mesh"},
		ClientAuth:   tls.NoClientCert,
	}, &quic.Config{
		MaxIncomingUniStreams: 0,
		MaxIdleTimeout:        120 * time.Second,
		KeepAlivePeriod:       15 * time.Second,
		EnableDatagrams:       true,
	})
	if err != nil {
		return nil, err
	}
	return ig, nil
}

func (ig *Ingress) Run(in, out chan []byte) {
	ig.runOnce.Do(func() {

		ig.in = in
		ig.out = out

		go func() {
			for data := range in {
				version := data[0] >> 4
				var packet gopacket.Packet
				switch version {
				case 4:
					packet = gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.DecodeOptions{
						Lazy:   true,
						NoCopy: true,
					})
				case 6:
					// Not supported ipv6
					continue
				}

				ipv4Layer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
				if ipv4Layer == nil {
					continue
				}
				targetIP := ipv4Layer.DstIP
				target, ex := ig.authorizedConnections.Get(targetIP.String())
				if !ex {
					continue
				}
				err := target.SendDatagram(data)
				if err != nil {
					log.Printf("failed to send datagram %d: %v", len(data), err)
				}
			}
		}()

		for {
			select {
			case <-ig.ctx.Done():
				return
			default:
			}

			conn, err := ig.lis.Accept(ig.ctx)
			if err != nil {
				log.Printf("failed to accept ingress connection: %v", err)
				continue
			}
			wc, err := wrapConnetion(conn, ig, func(c *IngressConnection) {
				ig.connections.Delete(c.ConnectionID())
				ig.authorizedConnections.Delete(c.GetVirtualIP().String())
			})
			if err != nil {
				log.Printf("failed to wrap ingress connection: %v", err)
				continue
			}
			ig.connections.Set(wc.ConnectionID(), wc)

			go wc.Run()
		}
	})
}

func (ig *Ingress) Authorize(ctx context.Context, source *IngressConnection, rq *ingressproto.AuthorizeRequest) (*ingressproto.AuthorizeResponse, error) {
	if source.Authorized() {
		reason := "already authorized"
		return &ingressproto.AuthorizeResponse{
			Ok:     false,
			Reason: &reason,
		}, nil
	}

	claims, userID, err := ig.jwtIss.Verify(rq.Token)
	if err != nil {
		reason := err.Error()
		return &ingressproto.AuthorizeResponse{
			Ok:     false,
			Reason: &reason,
		}, nil
	}
	_ = claims

	source.SetUserID(userID)

	// Get ip address for client
	ip, err := ig.ipAlloc.Get()
	if err != nil {
		log.Printf("failed to allocate ip for user: %v", err)
		reason := "server error"
		return &ingressproto.AuthorizeResponse{
			Ok:     false,
			Reason: &reason,
		}, nil
	}

	source.SetVirtualIP(ip)

	// Add connection to authorized
	ig.authorizedConnections.Set(ip.String(), source)

	return &ingressproto.AuthorizeResponse{
		Ok:         true,
		Reason:     nil,
		AssignedIp: ip.String(),
		PrefixLen:  16,
		Mtu:        1400,
		Routes:     []string{"0.0.0.0/0"},
		Dns:        []string{"8.8.8.8"},
	}, nil
}

func (ig *Ingress) Datagram(ctx context.Context, source *IngressConnection, data []byte) {
	if len(data) == 0 {
		return
	}
	version := data[0] >> 4
	var packet gopacket.Packet
	switch version {
	case 4:
		packet = gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.DecodeOptions{
			Lazy:   true,
			NoCopy: true,
		})
	case 6:
		// ipv6 is not supported
		return
	}

	ipv4Layer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ipv4Layer == nil {
		return
	}

	if !ipv4Layer.SrcIP.Equal(source.GetVirtualIP()) {
		ipv4Layer.SrcIP = source.GetVirtualIP()
		buffer := gopacket.NewSerializeBuffer()

		allLayers := packet.Layers()
		for _, layer := range allLayers {
			switch l := layer.(type) {
			case *layers.TCP:
				l.SetNetworkLayerForChecksum(ipv4Layer)
			case *layers.UDP:
				l.SetNetworkLayerForChecksum(ipv4Layer)
			}
		}
		serializableLayers := make([]gopacket.SerializableLayer, 0, len(allLayers))
		for _, layer := range allLayers {
			if s, ok := layer.(gopacket.SerializableLayer); ok {
				serializableLayers = append(serializableLayers, s)
			} else {
				return
			}
		}
		err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}, serializableLayers...)
		if err != nil {
			return
		}
		data = buffer.Bytes()
	}

	if ig.out != nil {
		ig.out <- data
	}
}
