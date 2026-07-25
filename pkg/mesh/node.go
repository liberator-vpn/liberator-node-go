package mesh

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/TexHik620953/liberator-node-go/internal/appconfig"
	"github.com/TexHik620953/liberator-node-go/internal/utils/quictransport"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/discovery"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/orchestrator"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/peerstore"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/transport"
	"google.golang.org/grpc"
)

type MeshNode struct {
	ctx          context.Context
	cfg          appconfig.MeshConfig
	peerStore    *peerstore.PeerStore
	connManager  transport.ConnectionManager
	grpcServer   *grpc.Server
	grpcLis      *quictransport.BiStreamLis
	orchestrator *orchestrator.DiscoveryOrchestrator
	localID      string
	router       orchestrator.Router
}

func New(
	ctx context.Context,
	cfg appconfig.MeshConfig,
	rootCa *x509.Certificate,
	nodeCert tls.Certificate,
	router orchestrator.Router,
) (*MeshNode, error) {
	localID, err := extractPeerID(nodeCert)
	if err != nil {
		return nil, err
	}

	ps := peerstore.NewPeerStore()
	if err := ps.Load(cfg.PeersStore); err != nil {
		log.Printf("Failed to load peer store: %v", err)
	}
	ps.InsertMerge(&peerstore.PeerInfo{
		Id:       localID,
		LastSeen: time.Now(),
	})

	caPool := x509.NewCertPool()
	caPool.AddCert(rootCa)
	cm, err := transport.NewConnectionManager(cfg, nodeCert, caPool)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection manager: %w", err)
	}

	grpcServer := grpc.NewServer()
	grpcLis := quictransport.NewBiStreamLis(ctx, cm.Addr())

	// Discovery сервис (регистрируется автоматически)
	_ = discovery.NewDiscoveryService(grpcServer, ps)

	discoveryCli := discovery.NewDiscoveryClient()
	orch := orchestrator.NewDiscoveryOrchestrator(ctx, localID, ps, cm, discoveryCli, router)

	return &MeshNode{
		ctx:          ctx,
		cfg:          cfg,
		peerStore:    ps,
		connManager:  cm,
		grpcServer:   grpcServer,
		grpcLis:      grpcLis,
		orchestrator: orch,
		localID:      localID,
		router:       router,
	}, nil
}

func (m *MeshNode) NodeID() string {
	return m.localID
}

func (n *MeshNode) Run() {
	// gRPC сервер
	go func() {
		if err := n.grpcServer.Serve(n.grpcLis); err != nil {
			log.Printf("gRPC server stopped: %v", err)
		}
	}()

	// Оркестратор
	n.orchestrator.Run()

	// Подключаемся к бутстрап-узлам
	go n.connectBootstrap()

	// Периодическое сохранение
	go n.saveLoop()

	<-n.ctx.Done()
	n.grpcServer.GracefulStop()
	n.grpcLis.Close()
	n.connManager.Close()
}

// connectBootstrap – подключается к бутстрап-узлам и передаёт соединения оркестратору
func (n *MeshNode) connectBootstrap() {
	for _, addr := range n.cfg.BootstrapAddrs {
		ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
		wconn, err := n.connManager.Dial(ctx, addr)
		cancel()
		if err != nil {
			log.Printf("Failed to dial bootstrap %s: %v", addr, err)
			continue
		}
		log.Printf("Connected to bootstrap %s (ID: %s)", addr, wconn.ID())
		// Передаём соединение оркестратору для обработки
		n.orchestrator.HandleConnection(wconn, false)
	}
}

// saveLoop – сохраняет PeerStore каждые 30 секунд
func (n *MeshNode) saveLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			if err := n.peerStore.Save(n.cfg.PeersStore); err != nil {
				log.Printf("Failed to save peer store: %v", err)
			}
		}
	}
}

// extractPeerID – извлекает ID из сертификата
func extractPeerID(cert tls.Certificate) (string, error) {
	if len(cert.Certificate) == 0 {
		return "", fmt.Errorf("no certificate data")
	}
	var leaf *x509.Certificate
	if cert.Leaf != nil {
		leaf = cert.Leaf
	} else {
		var err error
		leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return "", err
		}
	}
	hash := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(hash[:]), nil
}
