package transport

import (
	"context"
	"net"
)

// PeerConnection представляет абстракцию над QUIC Connection.
type PeerConnection interface {
	ID() string
	RemoteAddr() net.Addr
	OpenStream(ctx context.Context) (net.Conn, error)
	AcceptStream(ctx context.Context) (net.Conn, error)
	SendDatagram(data []byte) error
	RecvDatagram(ctx context.Context) ([]byte, error)
	IsInitiator() bool
	Close() error
	Context() context.Context
}

// NetworkTransport — интерфейс для создания входящих и исходящих соединений ноды.
type NetworkTransport interface {
	Dial(ctx context.Context, addr string) (PeerConnection, error)
	Accept(ctx context.Context) (PeerConnection, error)
	Addr() net.Addr
	Close() error
}
