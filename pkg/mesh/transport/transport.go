package transport

import (
	"context"
	"net"
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
