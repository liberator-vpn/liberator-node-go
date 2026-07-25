package session

import (
	"context"
	"errors"
	"net"
	"sync"
)

type BiStreamLis struct {
	ctx    context.Context
	cancel context.CancelFunc

	localAddr  net.Addr
	streamChan chan net.Conn
	closeOnce  sync.Once
}

// NewBiStreamLis создает виртуальный net.Listener для gRPC-сервера.
func NewBiStreamLis(ctx context.Context, localAddr net.Addr) *BiStreamLis {
	ctx, cancel := context.WithCancel(ctx)
	return &BiStreamLis{
		ctx:        ctx,
		cancel:     cancel,
		streamChan: make(chan net.Conn, 100), // Буферизируем для параллельных запросов
		localAddr:  localAddr,
	}
}

func (l *BiStreamLis) Addr() net.Addr {
	return l.localAddr
}

func (l *BiStreamLis) Accept() (net.Conn, error) {
	select {
	case conn, ok := <-l.streamChan:
		if !ok {
			return nil, errors.New("listener closed")
		}
		return conn, nil
	case <-l.ctx.Done():
		return nil, l.ctx.Err()
	}
}

func (l *BiStreamLis) Close() error {
	l.closeOnce.Do(func() {
		l.cancel()
		close(l.streamChan)
	})
	return nil
}

func (l *BiStreamLis) PushConnection(conn net.Conn) {
	select {
	case l.streamChan <- conn:
	case <-l.ctx.Done():
		_ = conn.Close()
	default:
		// Защита на случай переполнения: если очередь gRPC сервера перегружена,
		// мы сбрасываем входящий стрим, чтобы не вешать всю ноду.
		_ = conn.Close()
	}
}
