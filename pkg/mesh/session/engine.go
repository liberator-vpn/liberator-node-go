package session

import (
	"context"
	"log"

	"github.com/liberator-vpn/liberator-node-go/internal/utils/dgmessage"
	"github.com/liberator-vpn/liberator-node-go/pkg/mesh/transport"
)

// Router — минимальный интерфейс, через который сессии отдают датаграммы роутеру.
type Router interface {
	NewMessageCopyFrom(data []byte) (*dgmessage.DatagramMessage, error)
	HandleMeshPacket(packet *dgmessage.DatagramMessage)
}

// SessionEngine обслуживает соединения пула: регистрирует их в реестре
// (одна сессия на пира) и сливает входящие датаграммы в роутер.
type SessionEngine struct {
	registry Registry
	router   Router
}

func NewSessionEngine(reg Registry, router Router) *SessionEngine {
	return &SessionEngine{
		registry: reg,
		router:   router,
	}
}

// HandleConnection принимает и входящие, и исходящие QUIC-соединения пула.
func (e *SessionEngine) HandleConnection(ctx context.Context, pc transport.PeerConnection) {
	if pc == nil {
		return
	}

	s := &Session{
		PeerID: pc.ID(),
		Conn:   pc,
	}

	if err := e.registry.Add(s); err != nil {
		_ = pc.Close()
		return
	}

	go e.runSession(ctx, s)
}

func (e *SessionEngine) runSession(ctx context.Context, s *Session) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer e.registry.Remove(s)

	for {
		data, err := s.Conn.RecvDatagram(ctx)
		if err != nil {
			return
		}
		msg, err := e.router.NewMessageCopyFrom(data)
		if err != nil {
			log.Printf("failed to parse message: %v", err)
			continue
		}
		e.router.HandleMeshPacket(msg)
	}
}
