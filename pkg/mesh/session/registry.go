package session

import (
	"context"
	"errors"
	"sync"
)

type sessionRegistry struct {
	mu       sync.RWMutex
	localID  string
	sessions map[string]*Session
	subsMu   sync.Mutex
	subs     []chan *Session
}

func NewRegistry(localID string) Registry {
	return &sessionRegistry{
		localID:  localID,
		sessions: make(map[string]*Session),
		subs:     make([]chan *Session, 0),
	}
}
func (r *sessionRegistry) Add(s *Session) error {
	if s == nil || s.PeerID == "" {
		return errors.New("invalid session data")
	}

	r.mu.Lock()
	old, exists := r.sessions[s.PeerID]
	if exists {
		// Обнаружено дублирующее соединение! Применяем детерминированный алгоритм выборки:
		// Сравниваем ID нашей ноды с ID удаленной ноды
		weAreBigger := r.localID > s.PeerID

		if weAreBigger {
			// Если мы главные — мы хотим, чтобы между нами жило только ИСХОДЯЩЕЕ соединение.
			if s.Conn.IsInitiator() {
				// Новое соединение является исходящим? Отлично, значит старое (входящее) надо закрыть и заменить.
				r.mu.Unlock() // Выходим из мьютекса перед закрытием ресурсов
				_ = old.GrpcClient.Close()
				_ = old.Conn.Close()

				r.mu.Lock()
				r.sessions[s.PeerID] = s
			} else {
				// Новое соединение входящее? Но у нас уже есть наше исходящее. Отвергаем дубликат.
				r.mu.Unlock()
				return errors.New("duplicate connection rejected by tie-breaking rules (we keep outbound)")
			}
		} else {
			// Если мы ведомые — мы хотим, чтобы между нами жило только ВХОДЯЩЕЕ соединение соседа.
			if !s.Conn.IsInitiator() {
				// Новое соединение входящее? Отлично, закрываем наше старое исходящее и берем это.
				r.mu.Unlock()
				_ = old.GrpcClient.Close()
				_ = old.Conn.Close()

				r.mu.Lock()
				r.sessions[s.PeerID] = s
			} else {
				// Новое соединение исходящее? Но у соседа приоритет на входящее к нам. Отвергаем.
				r.mu.Unlock()
				return errors.New("duplicate connection rejected by tie-breaking rules (we keep inbound)")
			}
		}
	} else {
		// Дубликатов нет, просто сохраняем сессию
		r.sessions[s.PeerID] = s
	}
	r.mu.Unlock()

	// Оповещаем подписчиков только если сессия успешно закрепилась
	r.subsMu.Lock()
	for _, ch := range r.subs {
		select {
		case ch <- s:
		default:
		}
	}
	r.subsMu.Unlock()

	return nil
}

func (r *sessionRegistry) SubscribeNewSessions(ctx context.Context) <-chan *Session {
	ch := make(chan *Session, 100)

	r.subsMu.Lock()
	r.subs = append(r.subs, ch)
	r.subsMu.Unlock()

	// Удаляем канал из подписчиков при отмене контекста
	go func() {
		<-ctx.Done()
		r.subsMu.Lock()
		for i, sub := range r.subs {
			if sub == ch {
				r.subs = append(r.subs[:i], r.subs[i+1:]...)
				close(ch)
				break
			}
		}
		r.subsMu.Unlock()
	}()

	return ch
}

func (r *sessionRegistry) Remove(peerID string) {
	if peerID == "" {
		return
	}

	r.mu.Lock()
	s, exists := r.sessions[peerID]
	if !exists {
		r.mu.Unlock()
		return
	}
	delete(r.sessions, peerID)
	r.mu.Unlock()

	// Корректно высвобождаем ресурсы сокетов за пределами мьютекса
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
	if !exists {
		return nil, false
	}
	return s, true
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
