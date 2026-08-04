package session

import (
	"context"
	"net"
	"time"

	"github.com/TexHik620953/liberator-node-go/pkg/mesh/transport"
	"google.golang.org/grpc"
)

// Session объединяет абстрактное сетевое соединение пира и созданный поверх него gRPC-клиент.
type Session struct {
	PeerID     string
	Conn       transport.PeerConnection
	GrpcClient *grpc.ClientConn

	// AddedAt проставляет Registry.Add, по нему отличается коллизия dial'ов от переподключения.
	AddedAt time.Time
}

// Registry контролирует пул живых сессий с соседями в рантайме.
type Registry interface {
	Add(s *Session) error
	Remove(s *Session)
	Get(peerID string) (*Session, bool)
	ListActive() []*Session
	SubscribeNewSessions(ctx context.Context) <-chan *Session
	Close()
}

// StreamPusher — интерфейс для проброса виртуальных net.Conn стримов в grpc.Server.
type StreamPusher interface {
	PushConnection(conn net.Conn)
}
