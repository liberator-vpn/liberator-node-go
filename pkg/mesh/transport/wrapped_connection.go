package transport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/TexHik620953/liberator-node-go/internal/utils/quictransport"
	"github.com/quic-go/quic-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// WrappedConnection – интерфейс для работы с QUIC-соединением
type WrappedConnection interface {
	ID() string
	RemoteAddr() net.Addr
	Close()
	GrpcClient() *grpc.ClientConn

	SendDatagram(data []byte) error

	ReceiveDatagram(ctx context.Context) ([]byte, error)
	AcceptStream(ctx context.Context) (*quic.Stream, error)
}

// wrappedConnection – реализация
type wrappedConnection struct {
	nodeId     string
	conn       *quic.Conn
	grpcClient *grpc.ClientConn
}

// wrapConnection создаёт WrappedConnection из QUIC-соединения
func wrapConnection(conn *quic.Conn) (WrappedConnection, error) {
	state := conn.ConnectionState().TLS
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("peer is not authenticated")
	}
	peerCert := state.PeerCertificates[0]
	if len(peerCert.Subject.CommonName) == 0 {
		return nil, fmt.Errorf("peer has no common name")
	}
	hash := sha256.Sum256(peerCert.RawSubjectPublicKeyInfo)
	nodeId := hex.EncodeToString(hash[:])

	c := &wrappedConnection{
		nodeId: nodeId,
		conn:   conn,
	}

	grpcClient, err := newGrpcClientOverQuic(conn, conn.LocalAddr(), conn.RemoteAddr())
	if err != nil {
		return nil, err
	}
	c.grpcClient = grpcClient
	return c, nil
}

// newGrpcClientOverQuic создаёт gRPC-клиент поверх QUIC
func newGrpcClientOverQuic(quicConn *quic.Conn, local, remote net.Addr) (*grpc.ClientConn, error) {
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		stream, err := quicConn.OpenStreamSync(ctx)
		if err != nil {
			return nil, err
		}
		return quictransport.NewBiStreamConn(stream, local, remote), nil
	}
	return grpc.NewClient(
		"passthrough:///mesh-peer",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dialer),
	)
}

// Реализация методов
func (c *wrappedConnection) ID() string           { return c.nodeId }
func (c *wrappedConnection) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }
func (c *wrappedConnection) Close() {
	_ = c.conn.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "closed")
}
func (c *wrappedConnection) GrpcClient() *grpc.ClientConn   { return c.grpcClient }
func (c *wrappedConnection) SendDatagram(data []byte) error { return c.conn.SendDatagram(data) }

func (c *wrappedConnection) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return c.conn.ReceiveDatagram(ctx)
}

func (c *wrappedConnection) AcceptStream(ctx context.Context) (*quic.Stream, error) {
	return c.conn.AcceptStream(ctx)
}
