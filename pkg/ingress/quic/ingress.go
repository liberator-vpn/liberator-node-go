package ingressquic

import (
	"context"
	"crypto/tls"
	"fmt"
	"liberator-node-go/internal/utils/ipalloc"
	"liberator-node-go/internal/utils/routingtable"
	"liberator-node-go/internal/utils/safemap"
	"liberator-node-go/pkg/ingress"

	"log"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/quic-go/quic-go"
)

var _ ingress.Ingress = (*Ingress)(nil)

type Ingress struct {
	ctx context.Context
	cfg *IngressConfig

	routingTable routingtable.RoutingTable
	ipAlloc      *ipalloc.IPAllocator
	nodeID       string

	connectionsById safemap.Safemap[string, *IngressConnection]
	userIdToConnId  safemap.Safemap[string, string]

	udpBind   *net.UDPConn
	transport *quic.Transport
	lis       *quic.Listener
}

func New(
	ctx context.Context,
	cfg *IngressConfig,
	routingTable routingtable.RoutingTable,
	ipAlloc *ipalloc.IPAllocator,
	nodeID string,
) (*Ingress, error) {
	ig := &Ingress{
		ctx: ctx,
		cfg: cfg,

		routingTable: routingTable,
		ipAlloc:      ipAlloc,
		nodeID:       nodeID,

		connectionsById: safemap.New[string, *IngressConnection](),
		userIdToConnId:  safemap.New[string, string](),
	}
	var err error

	certificate, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to load cert key pair (%s, %s): %v", cfg.Cert, cfg.Key, err)
	}

	addr, err := net.ResolveUDPAddr("udp", cfg.ListenAddr)
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
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"mesh"},
		ClientAuth:   tls.NoClientCert,
	}, &quic.Config{
		MaxIncomingUniStreams: 0,
		MaxIdleTimeout:        120 * time.Second,
		KeepAlivePeriod:       15 * time.Second,
		EnableDatagrams:       true,
		MaxIncomingStreams:    1000,
		InitialPacketSize:     1400,
	})
	if err != nil {
		return nil, err
	}
	return ig, nil
}

func (ig *Ingress) Run(fromIng chan *routingtable.DatagramMessage) {
	for {
		select {
		case <-ig.ctx.Done():
			return
		default:
		}

		conn, err := ig.lis.Accept(ig.ctx)
		if err != nil {
			if ig.ctx.Err() != nil {
				return // Context done
			}
			log.Printf("failed to accept ingress connection: %v", err)
			continue
		}

		wc := wrapConnetion(conn, ig.nodeID)
		ig.connectionsById.Set(wc.id, wc)

		go ig.runConnection(wc, fromIng)
	}

}

func (ig *Ingress) runConnection(conn *IngressConnection, fromIng chan *routingtable.DatagramMessage) {
	defer func() {
		// Удаляем из таблицы маршрутизации (безопасно, даже если туда не добавляли)
		ig.routingTable.Delete(conn)

		// Освобождаем IP, если он был выделен
		if conn.virtualIp != nil {
			ig.ipAlloc.Free(conn.virtualIp)
		}

		// Чистим свои карты
		ig.connectionsById.Delete(conn.id)
		if conn.userID != uuid.Nil {
			ig.userIdToConnId.Delete(conn.userID.String())
		}

		// Физически закрываем QUIC (ignore error, так как могли закрыть с другой стороны)
		conn.Close()
	}()

	// ---------------------------------------------------------
	// ЭТАП 1: АВТОРИЗАЦИЯ (Тут будет вызов VpnAuthService)
	// ---------------------------------------------------------
	/*
	   Псевдокод того, что тут будет:
	   stream, err := ic.conn.AcceptStream(ig.ctx)
	   ticketID := readTicket(stream)

	   validatedTicket, err := ig.deps.AuthSvc.ValidateTicket(ig.ctx, ticketID)
	   if err != nil {
	       return // Сработает defer, соединение закроется
	   }

	   // Выдаем данные в объект
	   ic.SetUserId(validatedTicket.UserID)
	   ic.SetVirtualIp(validatedTicket.AssignedIP)

	   // Добавляем в роутинг
	   if err := ig.deps.RoutingTable.Add(ic); err != nil {
	       return // Сработает defer, IP вернется в пул
	   }

	   ig.userToConnID.Set(validatedTicket.UserID.String(), ic.id)
	*/

	// ---------------------------------------------------------
	// ЭТАП 2: ПРИЕМ ПАКЕТОВ
	// ---------------------------------------------------------
	for {
		data, err := conn.conn.ReceiveDatagram(ig.ctx)
		if err != nil {
			if ig.ctx.Err() == nil {
				log.Printf("ingress connection closed: %v", err)
			}
			return
		}

		// Если дошли сюда, значит юзер авторизован (иначе мы бы не дошли до цикла выше)
		msg, err := routingtable.NewDatagramMessage(data)
		if err != nil {
			continue // Дропаем невалидный IP фрейм
		}
		fromIng <- msg
	}
}

// KickUser реализует интерфейс для IngressManager
func (ig *Ingress) KickUser(ctx context.Context, userID string) bool {
	connID, exists := ig.userIdToConnId.Get(userID)
	if !exists {
		return false
	}

	ic, exists := ig.connectionsById.Get(connID)
	if !exists {
		return false
	}
	// Просто вызываем Close. Это заставит ReceiveDatagram в горутине
	// вернуть ошибку, горутина выйдет из цикла for и сработает defer!
	ic.Close()
	return true
}

/*
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
		portRules, err := ig.dbPool.Query().ListUserPortsRules(ctx, &userID)
		if err != nil {
			log.Printf("failed to list user port rules: %v", err)
			reason := "server error"
			return &ingressproto.AuthorizeResponse{
				Ok:     false,
				Reason: &reason,
			}, nil
		}

		for _, r := range portRules {
			params := routingtable.PortRule{
				User:           *r.User1,
				TargetUser:     r.TargetUser,
				Protocol:       r.Protocol,
				PortRangeStart: uint16(r.PortStart),
			}
			if r.PortEnd.Valid {
				v := uint16(r.PortEnd.Int32)
				params.PortRangeEnd = &v
			}
			ig.routingTable.AddRule(params)
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
			Mtu:        uint32(ig.mtu),
			Routes:     []string{"0.0.0.0/0"},
			Dns:        []string{ig.dnsServer}, // TODO: Fix this
		}, nil
	}
*/
