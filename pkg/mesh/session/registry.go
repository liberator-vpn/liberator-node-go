package session

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Окно, внутри которого встречные соединения считаются коллизией одновременного dial'а,
// а не переподключением пира. Дозвон ограничен таймаутом в 5 секунд, так что разъехаться
// сильнее пара соединений не может.
const collisionWindow = 10 * time.Second

type sessionRegistry struct {
	mu       sync.RWMutex
	localID  string
	sessions map[string]*Session
	subs     map[chan *Session]struct{}
	closed   bool
}

func NewRegistry(localID string) Registry {
	return &sessionRegistry{
		localID:  localID,
		sessions: make(map[string]*Session),
		subs:     make(map[chan *Session]struct{}),
	}
}

func (r *sessionRegistry) Add(s *Session) error {
	if s == nil || s.PeerID == "" || s.Conn == nil {
		return errors.New("invalid session data")
	}
	if s.PeerID == r.localID {
		return errors.New("self connection rejected")
	}

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return errors.New("session registry is closed")
	}

	old, exists := r.sessions[s.PeerID]
	if exists && old.Conn.Context().Err() == nil {
		if time.Since(old.AddedAt) < collisionWindow {
			// Встречный dial: обе ноды набрали друг друга почти одновременно.
			// Решаем детерминированно — выживает соединение, инициированное нодой
			// со старшим ID. Обе стороны считают предикат по одной и той же паре
			// соединений, поэтому приходят к одному ответу.
			keepOutbound := r.localID > s.PeerID
			if old.Conn.IsInitiator() == keepOutbound || s.Conn.IsInitiator() != keepOutbound {
				r.mu.Unlock()
				return errors.New("duplicate connection rejected by tie-breaking rules")
			}
		} else if s.Conn.IsInitiator() {
			// Наш лишний дозвон до пира, с которым сессия уже есть.
			r.mu.Unlock()
			return errors.New("duplicate outbound connection rejected")
		}
		// Иначе: пир заново к нам постучался спустя время после установки сессии.
		// Он не стал бы этого делать, считая сессию живой, значит он перезапустился,
		// а наша копия — зомби (QUIC узнает об этом только по MaxIdleTimeout).
	}

	fmt.Printf("new connection: %s\n", s.Conn.RemoteAddr().String())
	s.AddedAt = time.Now()
	r.sessions[s.PeerID] = s
	for ch := range r.subs {
		select {
		case ch <- s:
		default:
		}
	}
	r.mu.Unlock()

	if exists {
		closeSession(old)
	}

	return nil
}

func (r *sessionRegistry) SubscribeNewSessions(ctx context.Context) <-chan *Session {
	r.mu.Lock()
	ch := make(chan *Session, len(r.sessions)+100)
	if r.closed {
		close(ch)
		r.mu.Unlock()
		return ch
	}
	for _, s := range r.sessions {
		ch <- s
	}
	r.subs[ch] = struct{}{}
	r.mu.Unlock()

	go func() {
		<-ctx.Done()
		r.mu.Lock()
		if _, exists := r.subs[ch]; exists {
			delete(r.subs, ch)
			close(ch)
		}
		r.mu.Unlock()
	}()

	return ch
}

func (r *sessionRegistry) Remove(s *Session) {
	if s == nil || s.PeerID == "" {
		return
	}

	r.mu.Lock()
	current, exists := r.sessions[s.PeerID]
	if !exists || current != s {
		r.mu.Unlock()
		return
	}
	delete(r.sessions, s.PeerID)
	r.mu.Unlock()

	fmt.Printf("removed connection: %s\n", s.Conn.RemoteAddr().String())

	closeSession(s)
}

func (r *sessionRegistry) Close() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true

	sessions := make([]*Session, 0, len(r.sessions))
	for _, s := range r.sessions {
		sessions = append(sessions, s)
	}
	clear(r.sessions)

	for ch := range r.subs {
		delete(r.subs, ch)
		close(ch)
	}
	r.mu.Unlock()

	for _, s := range sessions {
		closeSession(s)
	}
}

func closeSession(s *Session) {
	if s.GrpcClient != nil {
		_ = s.GrpcClient.Close()
	}
	if s.Conn != nil {
		_ = s.Conn.Close()
	}
}

func (r *sessionRegistry) Get(peerID string) (*Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	s, exists := r.sessions[peerID]
	return s, exists
}

func (r *sessionRegistry) ListActive() []*Session {
	r.mu.RLock()
	defer r.mu.RUnlock()

	list := make([]*Session, 0, len(r.sessions))
	for _, s := range r.sessions {
		list = append(list, s)
	}
	return list
}
