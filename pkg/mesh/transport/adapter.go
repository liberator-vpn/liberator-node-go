package transport

import (
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

type biStreamConnAdapter struct {
	stream     *quic.Stream
	localAddr  net.Addr
	remoteAddr net.Addr
}

// NewBiStreamConn оборачивает QUIC-стрим в net.Conn.
func NewBiStreamConn(stream *quic.Stream, localAddr, remoteAddr net.Addr) net.Conn {
	return &biStreamConnAdapter{
		stream:     stream,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
}

func (b *biStreamConnAdapter) Read(p []byte) (n int, err error)  { return b.stream.Read(p) }
func (b *biStreamConnAdapter) Write(p []byte) (n int, err error) { return b.stream.Write(p) }
func (b *biStreamConnAdapter) Close() error                      { return b.stream.Close() }

func (b *biStreamConnAdapter) LocalAddr() net.Addr  { return b.localAddr }
func (b *biStreamConnAdapter) RemoteAddr() net.Addr { return b.remoteAddr }

func (b *biStreamConnAdapter) SetDeadline(t time.Time) error     { return b.stream.SetDeadline(t) }
func (b *biStreamConnAdapter) SetReadDeadline(t time.Time) error { return b.stream.SetReadDeadline(t) }
func (b *biStreamConnAdapter) SetWriteDeadline(t time.Time) error {
	return b.stream.SetWriteDeadline(t)
}
