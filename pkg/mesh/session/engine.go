package session

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	"github.com/TexHik620953/liberator-node-go/internal/utils/dgmessage"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/topology"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Router interface {
	NewMessageCopyFrom(data []byte) (*dgmessage.DatagramMessage, error)
	HandleMeshPacket(packet *dgmessage.DatagramMessage)
}

type SessionEngine struct {
	registry Registry
	pusher   StreamPusher
	repo     topology.PeerRepository
	router   Router
}

// NewSessionEngine собирает диспетчер сессионного трафика.
func NewSessionEngine(reg Registry, pusher StreamPusher, repo topology.PeerRepository, router Router) *SessionEngine {
	return &SessionEngine{
		registry: reg,
		pusher:   pusher,
		repo:     repo,
		router:   router,
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

	ctx, cancel := context.WithCancel(ctx)

	var wg sync.WaitGroup

	wg.Go(func() {
		defer cancel()
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
	})

	wg.Go(func() {
		defer cancel()
		for {
			select {
			case <-ctx.Done():
				return
			default:
				data, err := pc.RecvDatagram(ctx)
				if err != nil {
					log.Printf("failed to recv datagram: %v", err)
					continue
				}
				msg, err := e.router.NewMessageCopyFrom(data)
				if err != nil {
					log.Printf("failed to recv datagram: %v", err)
					continue
				}
				e.router.HandleMeshPacket(msg)
			}
		}
	})

	wg.Wait()
	e.registry.Remove(peerID)

}
