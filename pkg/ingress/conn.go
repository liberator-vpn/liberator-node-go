package ingress

import (
	"context"
	"liberator-node-go/internal/utils/quictransport"
	"liberator-node-go/pkg/ingress/ingressproto"
	"log"
	"net"

	"github.com/google/uuid"
	"github.com/quic-go/quic-go"
	"google.golang.org/grpc"
)

type IngressConnection struct {
	ingressproto.IngressServiceServer

	id string

	authorized bool
	userID     uuid.UUID
	virtualIp  net.IP

	ingress *Ingress
	conn    *quic.Conn

	grpcServer *grpc.Server
	grpcLis    *quictransport.BiStreamLis

	closeFunc func(c *IngressConnection)
}

func wrapConnetion(conn *quic.Conn, ingress *Ingress, closeFunc func(c *IngressConnection)) (*IngressConnection, error) {
	ic := &IngressConnection{
		id:      uuid.NewString(),
		conn:    conn,
		ingress: ingress,

		grpcServer: grpc.NewServer(),
		grpcLis:    quictransport.NewBiStreamLis(conn.Context(), conn.LocalAddr()),

		closeFunc: closeFunc,
		userID:    uuid.Nil,
		virtualIp: nil,
	}
	ingressproto.RegisterIngressServiceServer(ic.grpcServer, ic)

	return ic, nil
}

func (ic *IngressConnection) ConnectionID() string {
	return ic.id
}

func (ic *IngressConnection) GetAuthorized() bool {
	return ic.authorized
}
func (ic *IngressConnection) SetAuthorized() {
	ic.authorized = true
}

func (ic *IngressConnection) GetUserID() uuid.UUID {
	return ic.userID
}
func (ic *IngressConnection) SetUserID(userID uuid.UUID) {
	if ic.userID == uuid.Nil {
		ic.userID = userID
	}
}

func (ic *IngressConnection) SetVirtualIP(ip net.IP) {
	if ic.virtualIp == nil {
		ic.virtualIp = ip
	}
}
func (ic *IngressConnection) GetVirtualIP() net.IP {
	return ic.virtualIp
}

func (c *IngressConnection) Close() {
	_ = c.conn.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "closed")
}

func (ic *IngressConnection) Run() {
	ctx, cancel := context.WithCancel(ic.conn.Context())
	defer cancel()

	go ic.grpcServer.Serve(ic.grpcLis)

	go func() {
		for {
			biStream, err := ic.conn.AcceptStream(ctx)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				log.Printf("failed to accept stream: %v", err)
				return
			}

			netConn := quictransport.NewBiStreamConn(biStream, ic.conn.LocalAddr(), ic.conn.RemoteAddr())
			ic.grpcLis.PushConnection(netConn)
		}
	}()

	for {
		data, err := ic.conn.ReceiveDatagram(ctx)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			log.Printf("failed to read datagram: %v", err)
			break
		}
		// Drop unathorized
		if ic.userID != uuid.Nil {
			ic.ingress.Datagram(ctx, ic, data)
		}
	}

	ic.closeFunc(ic)
}

func (ic *IngressConnection) SendDatagram(data []byte) error {
	return ic.conn.SendDatagram(data)
}

func (ic *IngressConnection) Authorize(ctx context.Context, rq *ingressproto.AuthorizeRequest) (*ingressproto.AuthorizeResponse, error) {
	return ic.ingress.Authorize(ctx, ic, rq)
}
