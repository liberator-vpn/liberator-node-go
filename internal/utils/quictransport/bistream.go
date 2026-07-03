package quictransport

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

type BiStreamConnAdapter struct {
	conn *quic.Stream

	localAddr  net.Addr
	remoteAddr net.Addr
}

func NewBiStreamConn(stream *quic.Stream, localAddr, remoteAddr net.Addr) net.Conn {
	return &BiStreamConnAdapter{
		conn:       stream,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
}

// Close implements [net.Conn].
func (b *BiStreamConnAdapter) Close() error {
	return b.conn.Close()
}

// LocalAddr implements [net.Conn].
func (b *BiStreamConnAdapter) LocalAddr() net.Addr {
	return b.localAddr
}

// Read implements [net.Conn].
func (bc *BiStreamConnAdapter) Read(b []byte) (n int, err error) {
	return bc.conn.Read(b)
}

// RemoteAddr implements [net.Conn].
func (b *BiStreamConnAdapter) RemoteAddr() net.Addr {
	return b.remoteAddr
}

// SetDeadline implements [net.Conn].
func (b *BiStreamConnAdapter) SetDeadline(t time.Time) error {
	return b.conn.SetDeadline(t)
}

// SetReadDeadline implements [net.Conn].
func (b *BiStreamConnAdapter) SetReadDeadline(t time.Time) error {
	return b.conn.SetReadDeadline(t)
}

// SetWriteDeadline implements [net.Conn].
func (b *BiStreamConnAdapter) SetWriteDeadline(t time.Time) error {
	return b.conn.SetWriteDeadline(t)
}

// Write implements [net.Conn].
func (bc *BiStreamConnAdapter) Write(b []byte) (n int, err error) {
	return bc.conn.Write(b)
}

type BiStreamLis struct {
	ctx    context.Context
	cancel context.CancelFunc

	localAddr net.Addr

	streamChan chan net.Conn
	closeOnce  sync.Once
}

func NewBiStreamLis(ctx context.Context, localAddr net.Addr) *BiStreamLis {
	ctx, cancel := context.WithCancel(ctx)
	return &BiStreamLis{
		ctx:        ctx,
		cancel:     cancel,
		streamChan: make(chan net.Conn, 1),
		localAddr:  localAddr,
	}
}

func (l *BiStreamLis) Addr() net.Addr {
	return l.localAddr
}
func (l *BiStreamLis) Close() error {
	l.closeOnce.Do(func() {
		close(l.streamChan)
	})
	return nil
}
func (l *BiStreamLis) Accept() (net.Conn, error) {
	select {
	case conn := <-l.streamChan:
		return conn, nil
	case <-l.ctx.Done():
		return nil, errors.New("listener closed")
	}
}
func (l *BiStreamLis) PushConnection(conn net.Conn) {
	l.streamChan <- conn
}
