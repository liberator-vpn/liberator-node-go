package session

import (
	"context"
	"net"
	"time"

	"github.com/TexHik620953/liberator-node-go/pkg/mesh/topology"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type SessionEngine struct {
	registry Registry
	pusher   StreamPusher
	repo     topology.PeerRepository
}

// NewSessionEngine собирает диспетчер сессионного трафика.
func NewSessionEngine(reg Registry, pusher StreamPusher, repo topology.PeerRepository) *SessionEngine {
	return &SessionEngine{
		registry: reg,
		pusher:   pusher,
		repo:     repo, // <--- ДОБАВИТЬ
	}
}

func (e *SessionEngine) HandleConnection(ctx context.Context, pc transport.PeerConnection) {
	if pc == nil {
		return
	}

	peerID := pc.ID()

	// КЛЮЧЕВОЕ ИСПРАВЛЕНИЕ 1: Мгновенно регистрируем пира в репозитории.
	// LastSeen равен Now, ID и адрес известны. Аномалия Connections > Peers физически невозможна.
	e.repo.InsertMerge(topology.PeerInfo{
		ID:       peerID,
		Address:  pc.RemoteAddr().String(),
		LastSeen: time.Now(),
	})

	dialer := func(dialCtx context.Context, addr string) (net.Conn, error) {
		return pc.OpenStream(dialCtx)
	}

	grpcClient, err := grpc.NewClient(
		"passthrough:///mesh-peer",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dialer),
	)
	if err != nil {
		_ = pc.Close()
		return
	}

	s := &Session{
		PeerID:     peerID,
		Conn:       pc,
		GrpcClient: grpcClient,
	}

	// Вызов Add теперь отработает детерминированный Tie-Breaking
	if err := e.registry.Add(s); err != nil {
		_ = grpcClient.Close()
		_ = pc.Close()
		return
	}

	go func() {
		defer e.registry.Remove(peerID)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			stream, err := pc.AcceptStream(ctx)
			if err != nil {
				return
			}
			e.pusher.PushConnection(stream)
		}
	}()
}
