package transport

import (
	"context"
	"net"
	"time"
)

// PeerConnection представляет абстракцию над QUIC Connection.
type PeerConnection interface {
	ID() string
	RemoteAddr() net.Addr
	SendDatagram(data []byte) error
	RecvDatagram(ctx context.Context) ([]byte, error)
	IsInitiator() bool
	Close() error
	Context() context.Context

	TotalSent() uint64
	TotalRecv() uint64
	RTT() time.Duration
}

// ConnectionStats — счётчики уровня транспорта для диагностики. Позволяет
// отличить потери на mesh-канале (packets_lost) от блокировки приложения.
type ConnectionStats struct {
	MinRTT      time.Duration
	SmoothedRTT time.Duration
	BytesSent   uint64
	PacketsSent uint64
	BytesRecv   uint64
	PacketsRecv uint64
	BytesLost   uint64
	PacketsLost uint64
}

// StatsProvider реализуют транспорты, умеющие отдавать счётчики. Не входит в
// PeerConnection, чтобы не ломать тестовые реализации.
type StatsProvider interface {
	Stats() ConnectionStats
}

// NetworkTransport — интерфейс для создания входящих и исходящих соединений ноды.
type NetworkTransport interface {
	Dial(ctx context.Context, addr string) (PeerConnection, error)
	Accept(ctx context.Context) (PeerConnection, error)
	// SelfID возвращает идентичность этой ноды (SPKI её сертификата).
	SelfID() string
	Addr() net.Addr
	Close() error
}
