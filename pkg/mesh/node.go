package mesh

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"runtime"
	"sync"

	"github.com/TexHik620953/liberator-node-go/internal/appconfig"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/discovery"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/peerssync"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/session"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/topology"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/transport"
	"google.golang.org/grpc"
)

// MeshNode — публичный фасад библиотеки, управляющий жизненным циклом узла меш-сети.
type MeshNode struct {
	ctx        context.Context
	cancel     context.CancelFunc
	closeOnce  sync.Once
	grpcServer *grpc.Server
	localID    string

	// Внутренние компоненты, скрытые от пользователя библиотеки внутри internal/
	transport transport.NetworkTransport
	repo      topology.PeerRepository
	registry  session.Registry
	engine    *session.SessionEngine
	pusher    *session.BiStreamLis

	discoverySyncer *discovery.DiscoverySyncer
	peersSyncer     *peerssync.PeersSyncSyncer

	toMeshClients chan peerssync.RemoteMessage
}

// New собирает граф зависимостей и возвращает готовую к запуску mesh-ноду.
func New(ctx context.Context, cfg appconfig.MeshConfig, cert tls.Certificate, caPool *x509.CertPool, router Router) (*MeshNode, error) {
	quicTr, err := transport.NewQuicTransport(cfg.ListenAddr, cert, caPool)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize transport: %w", err)
	}
	node, err := NewWithTransport(ctx, cfg, cert, router, quicTr)
	if err != nil {
		_ = quicTr.Close()
		return nil, err
	}
	return node, nil
}

func NewWithTransport(
	ctx context.Context,
	cfg appconfig.MeshConfig,
	cert tls.Certificate,
	router Router,
	networkTransport transport.NetworkTransport,
) (*MeshNode, error) {
	if networkTransport == nil {
		return nil, fmt.Errorf("network transport is required")
	}

	ctx, cancel := context.WithCancel(ctx)

	localID, err := extractLocalPeerID(cert)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to extract local node ID: %w", err)
	}

	filePersister := topology.NewJsonFilePersister(cfg.PeersStore)
	repo := topology.NewPeerRepository(ctx, filePersister)

	pusher := session.NewBiStreamLis(ctx, networkTransport.Addr())
	reg := session.NewRegistry(localID)
	engine := session.NewSessionEngine(reg, pusher, repo, router)

	grpcServer := grpc.NewServer()

	discovery.RegisterDiscoveryService(grpcServer, repo)
	discoverySyncer := discovery.NewDiscoverySyncer(repo, reg, engine, networkTransport, cfg.BootstrapAddrs, localID)

	toMeshClient := make(chan peerssync.RemoteMessage, 1000)
	peerssync.RegisterPeersSyncServer(grpcServer, router)
	peersSyncer := peerssync.NewPeersSyncSyncer(ctx, reg, router, localID, toMeshClient)

	return &MeshNode{
		ctx:             ctx,
		cancel:          cancel,
		grpcServer:      grpcServer,
		localID:         localID,
		transport:       networkTransport,
		repo:            repo,
		registry:        reg,
		engine:          engine,
		discoverySyncer: discoverySyncer,
		peersSyncer:     peersSyncer,
		pusher:          pusher,
		toMeshClients:   toMeshClient,
	}, nil
}

func (n *MeshNode) CountPeers() int {
	return n.repo.Count()
}
func (n *MeshNode) CountConnections() int {
	return len(n.registry.ListActive())
}
func (n *MeshNode) ListenAddress() net.Addr {
	return n.transport.Addr()
}

// Run запускает параллельные воркеры сетевого обмена и блокирует поток до отмены контекста.
func (n *MeshNode) Run() {
	if n.ctx.Err() != nil {
		n.shutdown()
		return
	}

	var wg sync.WaitGroup

	wg.Go(func() {
		_ = n.grpcServer.Serve(n.pusher)
	})

	wg.Go(func() {
		for {
			conn, err := n.transport.Accept(n.ctx)
			if err != nil {
				return
			}
			if conn.ID() == n.localID {
				_ = conn.Close()
				continue
			}
			n.engine.HandleConnection(n.ctx, conn)
		}
	})

	wg.Go(func() {
		n.peersSyncer.Start(n.ctx)
	})

	wg.Go(func() {
		n.discoverySyncer.Start(n.ctx)
	})

	// Routines to send data to clients
	for range runtime.GOMAXPROCS(0) {
		wg.Go(func() {
			for {
				select {
				case <-n.ctx.Done():
					return
				case msg := <-n.toMeshClients:
					peer, ex := n.registry.Get(msg.TargetNodeID)
					if !ex {
						continue
					}
					peer.Conn.SendDatagram(msg.Data)
				}
			}
		})
	}

	<-n.ctx.Done()

	n.shutdown()
	wg.Wait()
	fmt.Println("node exit")
}

// Close останавливает меш-ноду и высвобождает все ресурсы.
func (n *MeshNode) Close() {
	n.shutdown()
}

func (n *MeshNode) shutdown() {
	n.closeOnce.Do(func() {
		n.cancel()
		_ = n.pusher.Close()
		n.grpcServer.Stop()
		n.registry.Close()
		_ = n.transport.Close()
	})
}

// NodeID возвращает уникальный хэш-идентификатор текущего узла.
func (n *MeshNode) NodeID() string {
	return n.localID
}

// Хелпер для извлечения SHA-256 публичного ключа (SPKI) из локального сертификата
func extractLocalPeerID(cert tls.Certificate) (string, error) {
	if len(cert.Certificate) == 0 {
		return "", fmt.Errorf("no certificate data provided")
	}

	var leaf *x509.Certificate
	if cert.Leaf != nil {
		leaf = cert.Leaf
	} else {
		var err error
		leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return "", fmt.Errorf("failed to parse x509 cert: %w", err)
		}
	}

	hash := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(hash[:]), nil
}
