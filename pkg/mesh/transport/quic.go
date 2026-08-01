package transport

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

type quicTransport struct {
	transport  *quic.Transport
	listener   *quic.Listener
	clientTLS  *tls.Config
	quicConfig *quic.Config
	localAddr  net.Addr
}

type quicPeerConnection struct {
	ctx         context.Context
	id          string
	conn        *quic.Conn
	isInitiator bool

	totalSent atomic.Uint64
	totalRecv atomic.Uint64
}

// NewQuicTransport инициализирует UDP-сокет, QUIC-транспорт и TLS конфигурации.
func NewQuicTransport(listenAddr string, cert tls.Certificate, caPool *x509.CertPool) (NetworkTransport, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve udp addr error: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen udp error: %w", err)
	}

	transport := &quic.Transport{Conn: udpConn}

	// Кастомная строгая mTLS валидация
	verifyPeer := func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return fmt.Errorf("peer certificate is missing")
		}

		// Так как мы включили InsecureSkipVerify для отключения проверки имени хоста,
		// мы ДОЛЖНЫ вручную проверить, что сертификат соседа подписан нашим общим Root CA.
		leaf := cs.PeerCertificates[0]
		_, err := leaf.Verify(x509.VerifyOptions{
			Roots:       caPool,
			CurrentTime: time.Now(),
			// Разрешаем сертификату быть валидным как для сервера, так и для клиента
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		})
		return err
	}

	clientTLS := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"mesh-quic"},
		// Отключаем стандартную проверку соответствия имени хоста (ServerName),
		// чтобы поддерживать любые кастомные имена (aboba, node1 и т.д.) в рамках меша
		InsecureSkipVerify: true,
		VerifyConnection:   verifyPeer,
	}

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"mesh-quic"},
		ClientCAs:    caPool,
		// На стороне сервера мы требуем сертификат от клиента и верифицируем его
		ClientAuth:       tls.RequireAndVerifyClientCert,
		VerifyConnection: verifyPeer,
	}

	quicConfig := &quic.Config{
		MaxIncomingUniStreams: 50,
		MaxIncomingStreams:    200,
		MaxIdleTimeout:        120 * time.Second,
		KeepAlivePeriod:       15 * time.Second,
		EnableDatagrams:       true,
	}

	listener, err := transport.Listen(serverTLS, quicConfig)
	if err != nil {
		_ = udpConn.Close()
		return nil, fmt.Errorf("quic listen error: %w", err)
	}

	return &quicTransport{
		transport:  transport,
		listener:   listener,
		clientTLS:  clientTLS,
		quicConfig: quicConfig,
		localAddr:  udpConn.LocalAddr(),
	}, nil
}

func (t *quicTransport) Dial(ctx context.Context, addr string) (PeerConnection, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	qConn, err := t.transport.Dial(ctx, udpAddr, t.clientTLS, t.quicConfig)
	if err != nil {
		return nil, err
	}
	return wrapConnection(qConn, true) // true — мы инициатор (Client)
}

func (t *quicTransport) Accept(ctx context.Context) (PeerConnection, error) {
	qConn, err := t.listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return wrapConnection(qConn, false) // false — к нам подключились (Server)
}

func (t *quicTransport) Addr() net.Addr { return t.localAddr }
func (t *quicTransport) Close() error   { return t.listener.Close() }

// Внутренний хелпер для сборки PeerConnection и извлечения ID соседа
func wrapConnection(qConn *quic.Conn, isInitiator bool) (PeerConnection, error) {
	state := qConn.ConnectionState().TLS
	if len(state.PeerCertificates) == 0 {
		_ = qConn.CloseWithError(0, "missing cert")
		return nil, fmt.Errorf("peer is unauthenticated")
	}

	leaf := state.PeerCertificates[0]
	hash := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	nodeID := hex.EncodeToString(hash[:])

	return &quicPeerConnection{
		ctx:         qConn.Context(),
		id:          nodeID,
		conn:        qConn,
		isInitiator: isInitiator,
	}, nil
}

// Реализация методов структуры quicPeerConnection
func (pc *quicPeerConnection) SendDatagram(data []byte) error {
	pc.totalSent.Add(uint64(len(data)))
	return pc.conn.SendDatagram(data)
}
func (pc *quicPeerConnection) RecvDatagram(ctx context.Context) ([]byte, error) {
	data, err := pc.conn.ReceiveDatagram(ctx)
	if err != nil {
		return nil, err
	}
	pc.totalRecv.Add(uint64(len(data)))
	return data, nil
}

func (pc *quicPeerConnection) TotalSent() uint64 {
	return pc.totalSent.Load()
}
func (pc *quicPeerConnection) TotalRecv() uint64 {
	return pc.totalRecv.Load()
}

func (pc *quicPeerConnection) Context() context.Context { return pc.ctx }
func (pc *quicPeerConnection) ID() string               { return pc.id }
func (pc *quicPeerConnection) RemoteAddr() net.Addr     { return pc.conn.RemoteAddr() }
func (pc *quicPeerConnection) Close() error {
	return pc.conn.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "session closed")
}
func (pc *quicPeerConnection) IsInitiator() bool { return pc.isInitiator }

func (pc *quicPeerConnection) OpenStream(ctx context.Context) (net.Conn, error) {
	stream, err := pc.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return NewBiStreamConn(stream, pc.conn.LocalAddr(), pc.conn.RemoteAddr()), nil
}

func (pc *quicPeerConnection) AcceptStream(ctx context.Context) (net.Conn, error) {
	stream, err := pc.conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return NewBiStreamConn(stream, pc.conn.LocalAddr(), pc.conn.RemoteAddr()), nil
}
