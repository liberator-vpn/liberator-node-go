package mesh

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/TexHik620953/liberator-node-go/internal/appconfig"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/discovery"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/session"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/topology"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/transport"
	"google.golang.org/grpc"
)

// MeshNode — публичный фасад библиотеки, управляющий жизненным циклом узла меш-сети.
type MeshNode struct {
	ctx        context.Context
	cancel     context.CancelFunc
	grpcServer *grpc.Server
	localID    string

	// Внутренние компоненты, скрытые от пользователя библиотеки внутри internal/
	transport transport.NetworkTransport
	repo      topology.PeerRepository
	registry  session.Registry
	engine    *session.SessionEngine
	syncer    *discovery.DiscoverySyncer
	pusher    *session.BiStreamLis
}

// New собирает граф зависимостей и возвращает готовую к запуску mesh-ноду.
func New(ctx context.Context, cfg appconfig.MeshConfig, cert tls.Certificate, caPool *x509.CertPool) (*MeshNode, error) {
	ctx, cancel := context.WithCancel(ctx)

	// 1. Извлекаем собственный NodeID из предоставленного TLS-сертификата
	localID, err := extractLocalPeerID(cert)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to extract local node ID: %w", err)
	}

	// 2. Инициализируем сетевой транспортный слой (quic-go mTLS)
	quicTr, err := transport.NewQuicTransport(cfg.ListenAddr, cert, caPool)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize transport: %w", err)
	}

	// 3. Настраиваем персистентность топологии на диске и репозиторий данных
	var filePersister topology.FilePersister
	if cfg.PeersStore != "" {
		filePersister = topology.NewJsonFilePersister(cfg.PeersStore)
	}
	repo := topology.NewPeerRepository(ctx, filePersister)

	// 4. Инициализируем слой сессий и виртуальный gRPC-листенер
	pusher := session.NewBiStreamLis(ctx, quicTr.Addr())
	reg := session.NewRegistry(localID)
	engine := session.NewSessionEngine(reg, pusher, repo)

	// 5. Разворачиваем gRPC сервер и регистрируем в нем DiscoveryService
	grpcServer := grpc.NewServer()
	discServer := discovery.NewDiscoveryServer(repo)

	discovery.RegisterDiscoveryService(grpcServer, discServer)

	// 6. Конструируем фоновый планировщик синхронизации
	syncer := discovery.NewDiscoverySyncer(repo, reg, engine, quicTr, cfg.BootstrapAddrs, localID)

	return &MeshNode{
		ctx:        ctx,
		cancel:     cancel,
		grpcServer: grpcServer,
		localID:    localID,
		transport:  quicTr,
		repo:       repo,
		registry:   reg,
		engine:     engine,
		syncer:     syncer,
		pusher:     pusher,
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
func (n *MeshNode) Run() error {
	var wg sync.WaitGroup

	// Поток 1: gRPC Server
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = n.grpcServer.Serve(n.pusher)
	}()

	// Поток 2: Accept Loop для входящих QUIC-соединений
	wg.Add(1)
	go func() {
		defer wg.Done()
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
	}()

	// Поток 3: Планировщик Discovery и реактивная подписка listenForNewPeers
	wg.Add(1)
	go func() {
		defer wg.Done()
		n.syncer.Start(n.ctx)
	}()

	// КЛЮЧЕВОЕ ИСПРАВЛЕНИЕ:
	// Даем горутине syncer.Start() пару миллисекунд, чтобы она успела вызвать repo.Subscribe()
	// и гарантированно встала на прослушивание канала событий.
	time.Sleep(10 * time.Millisecond)

	// Ожидаем завершения работы приложения
	<-n.ctx.Done()

	// Graceful Shutdown
	n.grpcServer.GracefulStop()
	_ = n.pusher.Close()
	_ = n.transport.Close()

	wg.Wait()
	return nil
}

// Close останавливает меш-ноду и высвобождает все ресурсы.
func (n *MeshNode) Close() {
	n.cancel()
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
