package session

import (
	"context"
	"log"
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

// RunWhileConnected крутит подписку на стрим, пока жива сессия. Без этого упавший стрим
// молча замораживает состояние пира: gRPC переподключит транспорт, но сам server-streaming
// вызов не возобновится, и апдейты (удаления правил, клиентов, пиров) перестанут приходить.
func RunWhileConnected(ctx context.Context, s *Session, name string, run func() error) {
	for {
		if err := run(); err != nil && ctx.Err() == nil && s.Conn.Context().Err() == nil {
			log.Printf("%s stream to peer %s stopped: %v", name, s.PeerID, err)
		}

		select {
		case <-ctx.Done():
			return
		case <-s.Conn.Context().Done():
			return
		case <-time.After(time.Second):
		}
	}
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
