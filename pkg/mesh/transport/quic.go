package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync/atomic"
	"time"

	"github.com/liberator-vpn/liberator-node-go/internal/metrics"

	"github.com/quic-go/quic-go"
)

// alpnToken превращает общий secret в ALPN-токен. Ноды подключаются только к тем,
// кто знает тот же secret: при несовпадении ALPN TLS-хендшейк не проходит.
func alpnToken(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return "liberator-" + hex.EncodeToString(sum[:8])
}

// makeEphemeralCert генерирует одноразовый самоподписанный сертификат для шифрования
// QUIC и получения идентичности ноды (SPKI). Криптография здесь не для аутентификации —
// её обеспечивает общий secret через ALPN.
func makeEphemeralCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "liberator-node"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

type quicTransport struct {
	transport  *quic.Transport
	listener   *quic.Listener
	clientTLS  *tls.Config
	quicConfig *quic.Config
	localAddr  net.Addr
	selfID     string
}

type quicPeerConnection struct {
	ctx         context.Context
	id          string
	conn        *quic.Conn
	isInitiator bool

	nextFragmentID atomic.Uint32
	reassembler    *datagramReassembler

	totalSent atomic.Uint64
	totalRecv atomic.Uint64
}

// NewQuicTransport инициализирует UDP-сокет, QUIC-транспорт и TLS. Аутентификация
// пиров — по общему secret (ALPN-токен), а не по цепочке сертификатов.
func NewQuicTransport(listenAddr, secret string) (NetworkTransport, error) {
	cert, err := makeEphemeralCert()
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral cert: %w", err)
	}
	token := alpnToken(secret)

	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve udp addr error: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen udp error: %w", err)
	}

	transport := &quic.Transport{Conn: udpConn}

	clientTLS := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		NextProtos:         []string{token},
		InsecureSkipVerify: true, // идентичность несёт ALPN-токен, а не CA
	}

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{token},
		// Запрашиваем клиентский сертификат (без верификации), чтобы получать его
		// ID (SPKI) — как и в случае с входящими, и для детекта «дозвона до себя».
		ClientAuth: tls.RequestClientCert,
	}

	quicConfig := &quic.Config{
		MaxIncomingUniStreams: 50,
		MaxIncomingStreams:    200,
		MaxIdleTimeout:        30 * time.Second,
		KeepAlivePeriod:       10 * time.Second,
		EnableDatagrams:       true,
		// InitialPacketSize не форсируем: на части путей между нодами
		// MTU меньше 1500 (проверено ping -M do: 1452+28 не проходит).
		// quic-go сам поднимет лимит через PMTUD, а SendDatagram уже умеет
		// откатываться на фрагментацию по DatagramTooLargeError.
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
		selfID:     spkiHashOfCert(&cert),
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
	return wrapConnection(qConn, true)
}

func (t *quicTransport) Accept(ctx context.Context) (PeerConnection, error) {
	qConn, err := t.listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return wrapConnection(qConn, false)
}

func (t *quicTransport) Addr() net.Addr { return t.localAddr }
func (t *quicTransport) Close() error   { return t.listener.Close() }
func (t *quicTransport) SelfID() string { return t.selfID }

// spkiHashOfCert возвращает SHA-256 SPKI сертификата как идентичность.
func spkiHashOfCert(c *tls.Certificate) string {
	var leaf *x509.Certificate
	if c.Leaf != nil {
		leaf = c.Leaf
	} else {
		if len(c.Certificate) == 0 {
			return ""
		}
		parsed, err := x509.ParseCertificate(c.Certificate[0])
		if err != nil {
			return ""
		}
		leaf = parsed
	}
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// wrapConnection извлекает ID соседа из SPKI его сертификата.
func wrapConnection(qConn *quic.Conn, isInitiator bool) (PeerConnection, error) {
	state := qConn.ConnectionState().TLS
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("peer did not present a certificate")
	}

	leaf := state.PeerCertificates[0]
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	nodeID := hex.EncodeToString(sum[:])

	return &quicPeerConnection{
		ctx:         qConn.Context(),
		id:          nodeID,
		conn:        qConn,
		isInitiator: isInitiator,
		reassembler: newDatagramReassembler(),
	}, nil
}

// Реализация методов структуры quicPeerConnection
func (pc *quicPeerConnection) SendDatagram(data []byte) error {
	metrics.ObserveTraffic(metrics.DirOut, metrics.PeerNode, metrics.NoProtocol, len(data))
	pc.totalSent.Add(uint64(len(data)))

	// Быстрый путь: одна QUIC DATAGRAM. Реальный лимит пути знает quic-go
	// (PMTUD); 1400 — верхняя граница для одной датаграммы. TCP-пакеты
	// ограничены max-clamp'ом MSS 1260 (inner 1300) и влезают; если не
	// влезли — фрагментируем ровно по лимиту, который вернул quic-go.
	if len(data) <= maxDirectDatagram {
		err := pc.conn.SendDatagram(data)
		if err == nil {
			return nil
		}
		var tooLarge *quic.DatagramTooLargeError
		if !errors.As(err, &tooLarge) {
			return err
		}
		return pc.sendFragmented(data, int(tooLarge.MaxDatagramPayloadSize))
	}
	// Пакет заведомо больше одной датаграммы: сразу режем безопасным
	// chunk'ом, чтобы не отправить половину фрагментов большим размером
	// и не упереться в лимит пути на середине.
	return pc.sendFragmented(data, defaultFragmentChunk+fragmentHeaderSize)
}

// sendFragmented отправляет пакет фрагментами. limit — максимальный размер
// одной QUIC DATAGRAM (payload + наш заголовок). Если фрагмент всё равно не
// влезает (лимит пути уменьшился между вызовами), делаем один retry с новым
// fragment id и размером из ошибки: старый частичный набор дочистит TTL.
func (pc *quicPeerConnection) sendFragmented(data []byte, limit int) error {
	chunk := limit - fragmentHeaderSize
	if chunk <= 0 || chunk > maxFragmentChunk {
		chunk = defaultFragmentChunk
	}
	err := sendFragments(pc.conn.SendDatagram, pc.nextFragmentID.Add(1), data, chunk)
	if err == nil {
		return nil
	}
	var tooLarge *quic.DatagramTooLargeError
	if !errors.As(err, &tooLarge) {
		return err
	}
	retry := int(tooLarge.MaxDatagramPayloadSize) - fragmentHeaderSize
	if retry <= 0 || retry >= chunk {
		return err
	}
	return sendFragments(pc.conn.SendDatagram, pc.nextFragmentID.Add(1), data, retry)
}
func (pc *quicPeerConnection) RecvDatagram(ctx context.Context) ([]byte, error) {
	data, err := pc.conn.ReceiveDatagram(ctx)
	if err != nil {
		return nil, err
	}
	if len(data) > 0 && data[0] == fragmentMagic {
		packet, ready, err := pc.reassembler.add(data)
		if err != nil {
			// Битый/неполный фрагмент не должен рвать всю QUIC-сессию:
			// дропаем его, TCP-поток повторит пакет, UDP потеряется.
			return nil, nil
		}
		if !ready {
			// Ещё не все фрагменты: вызывающий просто продолжит читать.
			return nil, nil
		}
		data = packet
	}
	metrics.ObserveTraffic(metrics.DirIn, metrics.PeerNode, metrics.NoProtocol, len(data))
	pc.totalRecv.Add(uint64(len(data)))
	return data, nil
}

func (pc *quicPeerConnection) TotalSent() uint64 {
	return pc.totalSent.Load()
}
func (pc *quicPeerConnection) TotalRecv() uint64 {
	return pc.totalRecv.Load()
}

func (pc *quicPeerConnection) RTT() time.Duration {
	return pc.conn.ConnectionStats().SmoothedRTT
}

// Stats отдаёт счётчики QUIC: RTT и потери пакетов на канале. По ним видно,
// упирается ли mesh-хоп в congestion control/потери, а не в CPU приложения.
func (pc *quicPeerConnection) Stats() ConnectionStats {
	st := pc.conn.ConnectionStats()
	return ConnectionStats{
		MinRTT:      st.MinRTT,
		SmoothedRTT: st.SmoothedRTT,
		BytesSent:   st.BytesSent,
		PacketsSent: st.PacketsSent,
		BytesRecv:   st.BytesReceived,
		PacketsRecv: st.PacketsReceived,
		BytesLost:   st.BytesLost,
		PacketsLost: st.PacketsLost,
	}
}

func (pc *quicPeerConnection) Context() context.Context { return pc.ctx }
func (pc *quicPeerConnection) ID() string               { return pc.id }
func (pc *quicPeerConnection) RemoteAddr() net.Addr     { return pc.conn.RemoteAddr() }
func (pc *quicPeerConnection) Close() error {
	return pc.conn.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "session closed")
}
func (pc *quicPeerConnection) IsInitiator() bool { return pc.isInitiator }
