package mesh

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/TexHik620953/liberator-node-go/internal/appconfig"
	"github.com/TexHik620953/liberator-node-go/internal/utils/quictransport"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/discovery"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/orchestrator"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/peerstore"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/transport"
	"google.golang.org/grpc"
)

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

	node := &MeshNode{
		ctx:        ctx,
		cfg:        cfg,
		peerStore:  peerstore.NewPeerStore(ctx, cfg.PeersStore),
		grpcServer: grpc.NewServer(),
		localID:    localID,
		router:     router,
	}

	node.peerStore.InsertMerge(&peerstore.PeerInfo{
		Id:       localID,
		LastSeen: time.Now(),
	})

	caPool := x509.NewCertPool()
	caPool.AddCert(rootCa)
	node.connManager, err = transport.NewConnectionManager(cfg, nodeCert, caPool)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection manager: %w", err)
	}

	node.grpcLis = quictransport.NewBiStreamLis(ctx, node.connManager.Addr())
	discoveryCli := discovery.NewDiscoveryClient()
	node.orchestrator = orchestrator.NewDiscoveryOrchestrator(ctx, localID, node.peerStore, node.connManager, discoveryCli, node.grpcLis, router)

	discovery.RegisterDiscoveryService(node.grpcServer, node.peerStore)

	// Передаем bootstrap ноды в peerStore
	for _, addr := range cfg.BootstrapAddrs {
		node.peerStore.InsertMerge(&peerstore.PeerInfo{
			Address: addr,
		})
	}

	return node, nil
}

func (m *MeshNode) NodeID() string {
	return m.localID
}
func (m *MeshNode) ListenAddr() string {
	return m.cfg.ListenAddr
}
func (m *MeshNode) ListConnections() []*peerstore.PeerInfo {
	return m.peerStore.List()
}

func (n *MeshNode) Run() {
	var wg sync.WaitGroup

	wg.Go(func() {
		n.grpcServer.Serve(n.grpcLis)
	})

	wg.Go(n.orchestrator.Run)

	<-n.ctx.Done()
	n.grpcServer.GracefulStop()
	n.grpcLis.Close()
	n.connManager.Close()

	wg.Wait()
}
