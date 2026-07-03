package ingress

import (
	"context"
	"liberator-node-go/ingress/ingressproto"
	"liberator-node-go/utils/quictransport"
	"log"
	"net"

	"github.com/google/uuid"
	"github.com/quic-go/quic-go"
	"google.golang.org/grpc"
)

type IngressConnection struct {
	ingressproto.IngressServiceServer

	id     string
	userID uuid.UUID

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
	}
	ingressproto.RegisterIngressServiceServer(ic.grpcServer, ic)

	return ic, nil
}

func (ic *IngressConnection) ConnectionID() string {
	return ic.id
}

func (ic *IngressConnection) UserID() uuid.UUID {
	return ic.userID
}
func (ic *IngressConnection) SetUserID(userID uuid.UUID) {
	ic.userID = userID
}
func (ic *IngressConnection) IsAuthorized() bool {
	return ic.userID != uuid.Nil
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
		ic.ingress.Datagram(ctx, ic, data)
	}

	ic.closeFunc(ic)
}

func (ic *IngressConnection) SendDatagram(data []byte) error {
	return ic.conn.SendDatagram(data)
}

func (ic *IngressConnection) Authorize(ctx context.Context, rq *ingressproto.AuthorizeRequest) (*ingressproto.AuthorizeResponse, error) {
	return ic.ingress.Authorize(ctx, ic, rq)
}
