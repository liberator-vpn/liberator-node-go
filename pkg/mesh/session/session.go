package session

import (
	"context"
	"time"

	"github.com/liberator-vpn/liberator-node-go/pkg/mesh/transport"
)

// Session объединяет абстрактное сетевое соединение пира в пуле.
type Session struct {
	PeerID string
	Conn   transport.PeerConnection

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
