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
	"liberator-node-go/internal/utils/cert"
	"liberator-node-go/internal/utils/peerstore"
	"liberator-node-go/internal/utils/quictransport"
	"liberator-node-go/internal/utils/routingtable"
	"liberator-node-go/pkg/mesh/services/discovery"
	"liberator-node-go/pkg/mesh/services/meshrouting"
	"log"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/quic-go/quic-go"
	"google.golang.org/grpc"
)

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
	ctx context.Context
	cfg appconfig.MeshConfig

	routingTable routingtable.RoutingTable

	cert         *tls.Certificate
	serverCaPool *x509.CertPool
	clientTls    *tls.Config

	// This server listener
	udpBind   *net.UDPConn
	transport *quic.Transport
	lis       *quic.Listener
	nodeId    string

	grpcServer *grpc.Server
	grpcLis    *quictransport.BiStreamLis

	peerStore *peerstore.PeerStore

	discovery   *discovery.DiscoveryService
	meshRouting *meshrouting.MeshRoutingService

	dgChan chan *routingtable.DatagramMessage
}

func New(ctx context.Context, cfg appconfig.MeshConfig, routingTable routingtable.RoutingTable) (*MeshNode, error) {
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
		peerStore:    peerstore.NewPeerStore(),
		routingTable: routingTable,

		dgChan: make(chan *routingtable.DatagramMessage, 500),
	}
	n.serverCaPool.AddCert(rootCa)

	// Load peerstore from file if file exists
	err = n.peerStore.Load(cfg.PeersStore)
	if err != nil {
		log.Printf("failed to load peerStore: %v", err)
	}

	n.meshRouting, err = meshrouting.New(n.grpcServer, n.peerStore, n.routingTable, n)
	if err != nil {
		return nil, fmt.Errorf("failed to create mesh rounting: %v", err)
	}
	n.discovery = discovery.New(n.grpcServer, n.peerStore)
	/*
		n.ipInfo, err = ipapi.GetIpInfo()
		if err != nil {
			return nil, err
		}*/
	// Add self to nodes
	n.peerStore.InsertMerge(&peerstore.PeerInfo{
		Id:       n.nodeId,
		LastSeen: time.Now(),
		Address:  "",
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
func (n *MeshNode) meshConnect(addr string) (peerstore.WrappedConnection, error) {
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
func (n *MeshNode) handleConnection(conn *quic.Conn, isIncoming bool) (peerstore.WrappedConnection, error) {
	meshConn, err := wrapConnection(conn, n.dgChan, n.grpcLis, func(mc peerstore.WrappedConnection) {
		n.peerStore.SetDisconnected(mc.ID())
	})
	if err != nil {
		return nil, err
	}
	if meshConn.ID() == n.nodeId {
		meshConn.Close()
		return nil, fmt.Errorf("cant connect to itself")
	}

	// Resolve collisions
	peer, ex := n.peerStore.Get(meshConn.ID())
	if ex && peer.Connected() {
		localID := n.nodeId
		remoteID := meshConn.ID()

		if localID < remoteID {
			if isIncoming {
				meshConn.Close()
				return peer.Connection, nil
			}
			peer.Connection.Close()
			log.Printf("Dial won collision against %s. Replacing.", meshConn.ID())
		} else {
			if !isIncoming {
				meshConn.Close()
				return peer.Connection, nil
			}
			peer.Connected()
			log.Printf("Incoming Accept won collision against %s. Replacing.", meshConn.ID())
		}
	} else {
		log.Printf("New mesh connection from %s", meshConn.ID())
	}

	// Store to peers store
	pi := &peerstore.PeerInfo{
		Id:         meshConn.ID(),
		LastSeen:   time.Now(),
		Address:    meshConn.RemoteAddr().String(),
		Connection: meshConn,
	}
	n.peerStore.InsertMerge(pi)
	go meshConn.Run()

	return meshConn, nil
}
func (n *MeshNode) Run() {
	// Grpc listener
	go n.grpcServer.Serve(n.grpcLis)

	// Services
	go n.discovery.Run(n.ctx)
	go n.meshRouting.Run(n.ctx)

	go n.connector()
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
func (n *MeshNode) connector() {
	ticker := time.NewTicker(time.Second * 10)
	go func() {
		for range ticker.C {
			go func() {
				for _, peer := range n.peerStore.List() {
					if n.peerStore.Connected(peer.Id) {
						continue
					}
					_, err := n.meshConnect(peer.Address)
					if err == nil {
						break
					}
				}
			}()
		}
	}()

	<-n.ctx.Done()
	ticker.Stop()
}

func (n *MeshNode) NodeID() string {
	return n.nodeId
}

func (n *MeshNode) DatagramChan() chan *routingtable.DatagramMessage {
	return n.dgChan
}

func (n *MeshNode) NewVirtualConnection(nodeID, userID, virtualIP string) (routingtable.RoutingObject, error) {
	uId, err := uuid.Parse(userID)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(virtualIP)

	return &VirtualConnection{
		Parent:    n,
		NodeID:    nodeID,
		UserID:    uId,
		VirtualIp: ip,
	}, nil
}
