package mesh

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

// static check
type wrappedConnection struct {
	nodeId     string
	conn       *quic.Conn
	grpcClient *grpc.ClientConn
}

func wrapConnection(conn *quic.Conn) (*wrappedConnection, error) {
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
	var err error
	c.grpcClient, err = c.newGrpcClient()
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (c *wrappedConnection) ID() string {
	return c.nodeId
}
func (c *wrappedConnection) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *wrappedConnection) Close() {
	_ = c.conn.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "closed")
}

func (c *wrappedConnection) GrpcClient() *grpc.ClientConn {
	return c.grpcClient
}
func (c *wrappedConnection) newGrpcClient() (*grpc.ClientConn, error) {
	// Настраиваем кастомный диалер для gRPC
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		stream, err := c.conn.OpenStreamSync(ctx)
		if err != nil {
			return nil, err
		}
		// Заворачиваем quic.Stream в net.Conn (структура streamConn из прошлого ответа)
		return quictransport.NewBiStreamConn(stream, c.conn.LocalAddr(), c.conn.RemoteAddr()), nil
	}

	// Устанавливаем виртуальное gRPC соединение
	grpcConn, err := grpc.NewClient(
		"passthrough:///mesh-peer",                               // Виртуальный адрес (gRPC требует непустую строку)
		grpc.WithTransportCredentials(insecure.NewCredentials()), // TLS уже проверен на уровне QUIC
		grpc.WithContextDialer(dialer),
	)
	if err != nil {
		return nil, err
	}

	return grpcConn, nil
}

func (c *wrappedConnection) SendDatagram(data []byte) error {
	return c.conn.SendDatagram(data)
}
