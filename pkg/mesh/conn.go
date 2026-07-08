package mesh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"liberator-node-go/internal/utils/peerstore"
	"liberator-node-go/internal/utils/quictransport"
	"net"
	"sync/atomic"

	"github.com/quic-go/quic-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// static check
type wrappedConnectionImpl struct {
	nodeId string
	conn   *quic.Conn

	isRunning uint32

	grpcLis    *quictransport.BiStreamLis
	grpcClient *grpc.ClientConn

	closeFunc func(c peerstore.WrappedConnection)

	dgChan chan []byte
}

func wrapConnection(conn *quic.Conn, dgChan chan []byte, grpcLis *quictransport.BiStreamLis, closeFunc func(c peerstore.WrappedConnection)) (peerstore.WrappedConnection, error) {
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

	c := &wrappedConnectionImpl{
		nodeId:    nodeId,
		conn:      conn,
		closeFunc: closeFunc,
		grpcLis:   grpcLis,
		dgChan:    dgChan,
	}
	var err error
	c.grpcClient, err = c.newGrpcClient()
	if err != nil {
		return nil, err
	}
	//c.meshService = meshproto.NewMeshServiceClient(c.defaultClient)

	return c, nil
}

func (c *wrappedConnectionImpl) ID() string {
	return c.nodeId
}
func (c *wrappedConnectionImpl) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *wrappedConnectionImpl) Close() {
	_ = c.conn.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "closed")
}

func (c *wrappedConnectionImpl) Run() {
	if !atomic.CompareAndSwapUint32(&c.isRunning, 0, 1) {
		return
	}

	ctx, cancel := context.WithCancel(c.conn.Context())
	defer cancel()

	go c.readDatagrams(ctx)
	c.acceptBiStreams(ctx)
	c.closeFunc(c)
}

func (c *wrappedConnectionImpl) readDatagrams(ctx context.Context) {
	for {
		data, err := c.conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		c.dgChan <- data
	}
}

func (c *wrappedConnectionImpl) acceptBiStreams(ctx context.Context) {
	for {
		stream, err := c.conn.AcceptStream(ctx)
		if err != nil {
			return
		}

		netConn := quictransport.NewBiStreamConn(stream, c.conn.LocalAddr(), c.conn.RemoteAddr())
		c.grpcLis.PushConnection(netConn)
	}
}

func (c *wrappedConnectionImpl) GrpcClient() *grpc.ClientConn {
	return c.grpcClient
}
func (c *wrappedConnectionImpl) newGrpcClient() (*grpc.ClientConn, error) {
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

func (c *wrappedConnectionImpl) SendDatagram(data []byte) error {
	return c.conn.SendDatagram(data)
}
