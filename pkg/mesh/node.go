package mesh

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"liberator-node-go/internal/appconfig"
	"liberator-node-go/internal/infra/ipapi"
	"liberator-node-go/internal/utils/cert"
	"liberator-node-go/internal/utils/quictransport"
	"liberator-node-go/internal/utils/safemap"
	"liberator-node-go/pkg/mesh/discovery"
	"log"
	"maps"
	"net"
	"os"
	"time"

	"github.com/quic-go/quic-go"
	"google.golang.org/grpc"
)

func fileExists(filename string) (bool, error) {
	_, err := os.Stat(filename)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err // ошибка доступа и т.д.
}

func extractPeerId(cert *tls.Certificate) (string, error) {
	if len(cert.Certificate) == 0 {
		return "", fmt.Errorf("tls certificate contains no raw chain data")
	}
	var leafCert *x509.Certificate
	var err error

	// 2. Если встроенный Leaf отсутствует, парсим его из сырых байт первого элемента
	if cert.Leaf != nil {
		leafCert = cert.Leaf
	} else {
		leafCert, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return "", fmt.Errorf("failed to parse raw tls certificate: %w", err)
		}
	}
	hash := sha256.Sum256(leafCert.RawSubjectPublicKeyInfo)
	nodeId := hex.EncodeToString(hash[:])

	return nodeId, nil
}

type MeshNode struct {
	ctx    context.Context
	ipInfo *ipapi.IpInfo
	cfg    appconfig.MeshConfig

	cert         *tls.Certificate
	serverCaPool *x509.CertPool

	// This server listener
	udpBind   *net.UDPConn
	transport *quic.Transport
	lis       *quic.Listener
	nodeId    string

	clientTls *tls.Config

	connections safemap.Safemap[string, WrappedConnection]

	grpcServer *grpc.Server
	grpcLis    *quictransport.BiStreamLis

	peerStore *discovery.PeerStore
	discovery *discovery.DiscoveryService[WrappedConnection]
}

func (n *MeshNode) Discovery() *discovery.DiscoveryService[WrappedConnection] {
	return n.discovery
}
func (n *MeshNode) PeerStore() *discovery.PeerStore {
	return n.peerStore
}
func (n *MeshNode) ConnectionsCount() int {
	return n.connections.Count()
}
func (n *MeshNode) Addr() net.Addr {
	return n.lis.Addr()
}
func New(ctx context.Context, cfg appconfig.MeshConfig) (*MeshNode, error) {
	// Load certs
	rootCa, err := cert.ReadCertificateFromFile(cfg.RootCert)
	if err != nil {
		return nil, fmt.Errorf("failed to load root cert: %v", err)
	}

	nodeCert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to load node cert: %v", err)
	}

	nodeId, err := extractPeerId(&nodeCert)
	if err != nil {
		return nil, err
	}

	n := &MeshNode{
		ctx:          ctx,
		cfg:          cfg,
		cert:         &nodeCert,
		serverCaPool: x509.NewCertPool(),
		grpcServer:   grpc.NewServer(),
		nodeId:       nodeId,
		peerStore:    discovery.NewPeerStore(),
		connections:  safemap.New[string, WrappedConnection](),
	}
	n.serverCaPool.AddCert(rootCa)

	// Load peerstore from file if file exists
	ex, _ := fileExists(cfg.PeersStore)
	if ex {
		err = n.peerStore.Load(cfg.PeersStore)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("failed to load peerstore: %v", err)
			}
		}
	}

	n.discovery = discovery.New(n.grpcServer, n.peerStore, n.connections)
	/*
		n.ipInfo, err = ipapi.GetIpInfo()
		if err != nil {
			return nil, err
		}*/
	// Add self to nodes
	n.peerStore.InsertMerge(&discovery.PeerInfo{
		Id:        n.nodeId,
		LastSeen:  time.Now(),
		IpInfo:    n.ipInfo,
		Addresses: map[string]bool{},
	})

	addr, err := net.ResolveUDPAddr("udp", cfg.ListenAddr)
	if err != nil {
		return nil, err
	}

	n.udpBind, err = net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	n.transport = &quic.Transport{
		Conn: n.udpBind,
	}

	n.clientTls = &tls.Config{
		Certificates: []tls.Certificate{*n.cert},
		NextProtos:   []string{"mesh"},

		// 1. Отключаем дефолтную проверку по ServerName (так как мы его не знаем)
		InsecureSkipVerify: true,
		// 2. Пишем кастомную валидацию соединения
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("target peer does not sent cert")
			}

			leafCert := cs.PeerCertificates[0]

			// Вручную запускаем валидацию цепочки по нашему CA пуллу.
			// Это защищает от Man-in-the-Middle атак.
			_, err := leafCert.Verify(x509.VerifyOptions{
				Roots:       n.serverCaPool,
				CurrentTime: time.Now(),
				KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			})
			if err != nil {
				return fmt.Errorf("failed to verify peer cert: %w", err)
			}
			// Узел успешно прошел проверку! Запоминаем его логическое имя из сертификата
			return nil
		},
	}
	n.lis, err = n.transport.Listen(&tls.Config{
		Certificates: []tls.Certificate{*n.cert},
		NextProtos:   []string{"mesh"},
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("target peer does not sent cert")
			}
			leafCert := cs.PeerCertificates[0]
			_, err := leafCert.Verify(x509.VerifyOptions{
				Roots:       n.serverCaPool,
				CurrentTime: time.Now(),
				KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			})
			if err != nil {
				return fmt.Errorf("failed to verify peer cert: %w", err)
			}
			return nil
		},
	}, &quic.Config{
		MaxIncomingUniStreams: 0,
		MaxIdleTimeout:        120 * time.Second,
		KeepAlivePeriod:       15 * time.Second,
		EnableDatagrams:       true,
	})
	if err != nil {
		return nil, err
	}

	n.grpcLis = quictransport.NewBiStreamLis(ctx, n.lis.Addr())
	log.Printf("created node with id: %s", n.nodeId)
	return n, nil
}
func (n *MeshNode) meshConnect(addr string) (WrappedConnection, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := n.transport.Dial(n.ctx, udpAddr, n.clientTls, &quic.Config{
		MaxIncomingUniStreams: 0,
		MaxIdleTimeout:        120 * time.Second,
		KeepAlivePeriod:       15 * time.Second,
		EnableDatagrams:       true,
	})
	if err != nil {
		return nil, err
	}
	return n.handleConnection(conn, false)
}
func (n *MeshNode) handleConnection(conn *quic.Conn, isIncoming bool) (WrappedConnection, error) {
	meshConn, err := wrapConnection(conn, n.grpcLis, func(mc WrappedConnection) {
		n.connections.Delete(mc.ID())
	})
	if err != nil {
		return nil, err
	}
	if meshConn.ID() == n.nodeId {
		meshConn.Close()
		return nil, fmt.Errorf("cant connect to itself")
	}

	// Resolve collisions
	original, ex := n.connections.Get(meshConn.ID())
	if ex {
		localID := n.nodeId
		remoteID := meshConn.ID()

		if localID < remoteID {
			if isIncoming {
				meshConn.Close()
				return original, nil
			}
			original.Close()
			log.Printf("Dial won collision against %s. Replacing.", meshConn.ID())
		} else {
			if !isIncoming {
				meshConn.Close()
				return original, nil
			}
			original.Close()
			log.Printf("Incoming Accept won collision against %s. Replacing.", meshConn.ID())
		}
	}

	if n.connections.Exists(meshConn.ID()) {
		log.Println("duplicated")
	}

	n.connections.Set(meshConn.ID(), meshConn)
	// Store to peers store
	pi := &discovery.PeerInfo{
		Id:       meshConn.ID(),
		LastSeen: time.Now(),
		IpInfo:   n.ipInfo,
		Addresses: map[string]bool{
			meshConn.RemoteAddr().String(): true,
		},
	}
	n.peerStore.InsertMerge(pi)
	go meshConn.Run()

	return meshConn, nil
}
func (n *MeshNode) Run() {
	// Grpc listener
	go n.grpcServer.Serve(n.grpcLis)

	go n.nodeWorker()

	// Connect to bootstrap nodes
	go func() {
		for _, bn := range n.cfg.BootstrapAddrs {
			_, err := n.meshConnect(bn)
			if err != nil {
				log.Printf("failed to connect to bootstrap node %s: %v", bn, err)
			}
		}
	}()

	// Save peers store every 30 seconds
	go func() {
		t := time.NewTicker(time.Second * 30)
		defer t.Stop()
		for {
			select {
			case <-n.ctx.Done():
				return
			case <-t.C:
				err := n.peerStore.Save(n.cfg.PeersStore)
				if err != nil {
					log.Printf("failed to save peer store: %v", err)
				}
			}
		}
	}()

	// Accept connections
	for {
		select {
		case <-n.ctx.Done():
			n.lis.Close()
			n.grpcLis.Close()
			return
		default:
		}
		conn, err := n.lis.Accept(n.ctx)

		if err != nil {
			if errors.Is(err, quic.ErrServerClosed) || errors.Is(err, context.Canceled) {
				return
			}
			log.Printf("failed to accept connection: %v", err)
			continue
		}
		go func() {
			meshConn, err := n.handleConnection(conn, true)
			if err != nil && meshConn != nil {
				meshConn.Close()
			}
		}()
	}
}

func (n *MeshNode) nodeWorker() {
	go n.discovery.Run(n.ctx)

	go func() {
		ticker := time.NewTicker(time.Second * 5)
		for range ticker.C {
			go func() {
				for _, peer := range n.peerStore.List() {
					if n.connections.Exists(peer.Id) {
						continue
					}
					peer.AddrMut.Lock()
					addrClone := maps.Clone(peer.Addresses)
					peer.AddrMut.Unlock()
					for a, _ := range addrClone {
						_, err := n.meshConnect(a)
						if err == nil {
							break
						}
					}
				}
			}()
		}
	}()

	select {
	case <-n.ctx.Done():
	}
}
