package ingress

import (
	"context"
	"crypto/tls"
	"liberator-node-go/egress"
	"liberator-node-go/ingress/ingressproto"
	"liberator-node-go/utils/ipalloc"
	"liberator-node-go/utils/liberatorjwt"
	"liberator-node-go/utils/safemap"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/quic-go/quic-go"
	"github.com/songgao/packets/ethernet"
)

type Ingress struct {
	ctx  context.Context
	cert *tls.Certificate

	udpBind   *net.UDPConn
	transport *quic.Transport
	lis       *quic.Listener

	jwtSecret []byte

	connections safemap.Safemap[string, *IngressConnection]
	// By virtual ip
	authorizedConnections safemap.Safemap[string, *IngressConnection]

	egr *egress.Egress

	ipAlloc *ipalloc.IPAllocator
}

func New(ctx context.Context, lisAddr string, jwtSecret []byte, cert *tls.Certificate) (*Ingress, error) {
	ig := &Ingress{
		ctx:                   ctx,
		cert:                  cert,
		connections:           safemap.New[string, *IngressConnection](),
		authorizedConnections: safemap.New[string, *IngressConnection](),
		jwtSecret:             jwtSecret,
	}
	var err error

	ig.ipAlloc, err = ipalloc.New("10.8.0.0/16")
	if err != nil {
		return nil, err
	}

	ig.egr, err = egress.New("liberator", "10.8.0.0/16", "enp11s0")
	if err != nil {
		panic(err)
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

func (ig *Ingress) Run() {
	go func() {
		var frame ethernet.Frame
		frame.Resize(1500)
		for {
			n, err := ig.egr.Read(frame)
			if err != nil {
				log.Printf("failed to read from egr: %v", err)
				continue
			}
			data := frame[:n]

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
			err = target.SendDatagram(data)
			if err != nil {
				log.Printf("failed to send datagram: %v", err)
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
}

func (ig *Ingress) Authorize(ctx context.Context, source *IngressConnection, rq *ingressproto.AuthorizeRequest) (*ingressproto.AuthorizeResponse, error) {
	if source.Authorized() {
		reason := "already authorized"
		return &ingressproto.AuthorizeResponse{
			Ok:     false,
			Reason: &reason,
		}, nil
	}

	claims, userID, err := liberatorjwt.Verify(rq.Token, ig.jwtSecret)
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

	// Milestone 1: static tunnel configuration. A real allocator will hand out
	// per-session IPs; for now every client gets the same config, which is
	// enough to validate connect + authorize + datagram-send.
	return &ingressproto.AuthorizeResponse{
		Ok:         true,
		Reason:     nil,
		AssignedIp: ip.String(),
		PrefixLen:  24,
		Mtu:        1400,
		Routes:     []string{"0.0.0.0/0"},
		Dns:        []string{"1.1.1.1"},
	}, nil
}

func (ig *Ingress) Datagram(ctx context.Context, source *IngressConnection, data []byte) {
	if len(data) == 0 {
		return
	}
	// TODO: manually set source ip to frame, so user cant change it.

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
		return
	}

	ipv4Layer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ipv4Layer == nil {
		return
	}

	if !ipv4Layer.SrcIP.Equal(source.GetVirtualIP()) {
		// We need to manually set ip for packet
		ipv4Layer.SrcIP = source.GetVirtualIP()
		// TODO: fix allocations here
		buffer := gopacket.NewSerializeBuffer()
		err := ipv4Layer.SerializeTo(buffer, gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		})
		if err != nil {
			return
		}
		data = buffer.Bytes()
	}

	n, err := ig.egr.Write(data)
	if err != nil {
		log.Printf("failed to write to egr: %v", err)
		return
	}
	if n != len(data) {
		log.Printf("write egr size len missmatch: %v", err)
		return
	}
}
