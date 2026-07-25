package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/TexHik620953/liberator-node-go/internal/appconfig"
	"github.com/quic-go/quic-go"
)

type ConnectionManager interface {
	Dial(ctx context.Context, addr string) (WrappedConnection, error)
	Accept(ctx context.Context) (WrappedConnection, error)
	Close() error
	Addr() net.Addr
}

type quicConnectionManager struct {
	transport  *quic.Transport
	listener   *quic.Listener
	tlsConfig  *tls.Config
	quicConfig *quic.Config
	localAddr  net.Addr
	cert       tls.Certificate
	caPool     *x509.CertPool
}

func NewConnectionManager(cfg appconfig.MeshConfig, cert tls.Certificate, caPool *x509.CertPool) (ConnectionManager, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", cfg.ListenAddr)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	transport := &quic.Transport{Conn: udpConn}

	clientTLS := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		NextProtos:         []string{"mesh"},
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("no peer certificate")
			}
			leaf := cs.PeerCertificates[0]
			_, err := leaf.Verify(x509.VerifyOptions{
				Roots:       caPool,
				CurrentTime: time.Now(),
				KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			})
			return err
		},
	}

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"mesh"},
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("no peer certificate")
			}
			leaf := cs.PeerCertificates[0]
			_, err := leaf.Verify(x509.VerifyOptions{
				Roots:       caPool,
				CurrentTime: time.Now(),
				KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			})
			return err
		},
	}

	quicConfig := &quic.Config{
		MaxIncomingUniStreams: 0,
		MaxIdleTimeout:        120 * time.Second,
		KeepAlivePeriod:       15 * time.Second,
		EnableDatagrams:       true,
	}

	listener, err := transport.Listen(serverTLS, quicConfig)
	if err != nil {
		return nil, err
	}

	return &quicConnectionManager{
		transport:  transport,
		listener:   listener,
		tlsConfig:  clientTLS,
		quicConfig: quicConfig,
		localAddr:  udpAddr,
		cert:       cert,
		caPool:     caPool,
	}, nil
}

func (m *quicConnectionManager) Dial(ctx context.Context, addr string) (WrappedConnection, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	quicConn, err := m.transport.Dial(ctx, udpAddr, m.tlsConfig, m.quicConfig)
	if err != nil {
		return nil, err
	}
	return wrapConnection(quicConn)
}

func (m *quicConnectionManager) Accept(ctx context.Context) (WrappedConnection, error) {
	quicConn, err := m.listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return wrapConnection(quicConn)
}

func (m *quicConnectionManager) Close() error {
	return m.listener.Close()
}

func (m *quicConnectionManager) Addr() net.Addr {
	return m.localAddr
}
