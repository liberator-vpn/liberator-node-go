package ingress

import (
	"context"
	"crypto/tls"
	"liberator-node-go/internal/infra/repos"
	"liberator-node-go/internal/utils/ipalloc"
	"liberator-node-go/internal/utils/liberatorjwt"
	"liberator-node-go/internal/utils/routingtable"
	"liberator-node-go/internal/utils/safemap"
	"liberator-node-go/pkg/ingress/ingressproto"
	"sync"

	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
	"github.com/quic-go/quic-go"
)

type DatagramMessage struct {
	Data  []byte
	User  uuid.UUID
	SrcIP net.IP
	DstIP net.IP
}

type Ingress struct {
	ctx  context.Context
	cert *tls.Certificate

	udpBind   *net.UDPConn
	transport *quic.Transport
	lis       *quic.Listener

	jwtIss *liberatorjwt.LiberatorJWT

	connections safemap.Safemap[string, *IngressConnection]

	ipAlloc *ipalloc.IPAllocator

	in, out chan *DatagramMessage

	runOnce sync.Once

	routingTable routingtable.RoutingTable

	dbPool *repos.DbPool
}

func New(
	ctx context.Context,
	routingTable routingtable.RoutingTable,
	ipAlloc *ipalloc.IPAllocator,
	lisAddr string,
	jwtIss *liberatorjwt.LiberatorJWT,
	cert *tls.Certificate,
	dbPool *repos.DbPool,
) (*Ingress, error) {
	ig := &Ingress{
		ctx:          ctx,
		cert:         cert,
		routingTable: routingTable,
		jwtIss:       jwtIss,
		ipAlloc:      ipAlloc,
		dbPool:       dbPool,

		connections: safemap.New[string, *IngressConnection](),
	}
	var err error

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

func (ig *Ingress) Run(out chan *DatagramMessage) {
	ig.runOnce.Do(func() {
		ig.out = out

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
				ig.routingTable.Delete(c)
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
	if source.GetAuthorized() {
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
	source.SetUserID(userID)
	source.SetVirtualIP(ip)
	source.SetAuthorized()

	// Get user allowed list
	allowedList, err := ig.dbPool.Query().ListUserApprovedInterconnections(ctx, &userID)
	if err != nil {
		log.Printf("failed to list user allowed interconnections: %v", err)
		reason := "server error"
		return &ingressproto.AuthorizeResponse{
			Ok:     false,
			Reason: &reason,
		}, nil
	}
	for _, r := range allowedList {
		if r.User1ID == nil || r.User2ID == nil {
			continue
		}
		ig.routingTable.Allow(*r.User1ID, *r.User2ID)
	}

	// Add connection to routing table
	err = ig.routingTable.Add(source)
	if err != nil {
		log.Printf("failed to add ingress connection to routing table: %v", err)
		reason := "server error"
		return &ingressproto.AuthorizeResponse{
			Ok:     false,
			Reason: &reason,
		}, nil
	}

	// Load list of allowed interconnections for user

	return &ingressproto.AuthorizeResponse{
		Ok:         true,
		Reason:     nil,
		AssignedIp: ip.String(),
		PrefixLen:  16,
		Mtu:        1400,
		Routes:     []string{"0.0.0.0/0"},
		Dns:        []string{"8.8.8.8"}, // TODO: Fix this
	}, nil
}

func (ig *Ingress) Datagram(ctx context.Context, source *IngressConnection, data []byte) {
	if ig.out == nil {
		return
	}
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

	ipv4LayerSt := packet.Layer(layers.LayerTypeIPv4)
	if ipv4LayerSt == nil {
		return
	}
	ipv4Layer := ipv4LayerSt.(*layers.IPv4)

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

	ig.out <- &DatagramMessage{
		Data:  data,
		User:  source.GetUserID(),
		SrcIP: source.GetVirtualIP(),
		DstIP: ipv4Layer.DstIP,
	}
}
