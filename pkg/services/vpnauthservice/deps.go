package vpnauthservice

import (
	"context"
	"time"
)

// TicketStore отвечает за хранение одноразовых билетов (обычно Redis).
type TicketStore interface {
	// Set сохраняет билет с заданным TTL.
	Set(ctx context.Context, ticketID string, data *ValidatedTicket, ttl time.Duration) error
	// GetAndDelete атомарно забирает билет из хранилища (одноразовость).
	// Если билета нет или он просрочен - возвращает ошибку.
	GetAndDelete(ctx context.Context, ticketID string) (*ValidatedTicket, error)
}

// UserRepository работает с вашей основной БД (Postgres).
type UserRepository interface {
	// GetUserLimits достает лимиты трафика/скорости для пользователя.
	GetUserLimits(ctx context.Context, userID string) (UserLimits, error)

	// FindUserIDByPublicKey ищет юзера по персистентному ключу (для Флоя 2).
	// Возвращает пустую строку и nil, если ключ валиден, но не привязан к юзеру (аноним).
	FindUserIDByPublicKey(ctx context.Context, pubKey string) (string, error)

	// IsKeyRevoked проверяет, не отозван ли персистентный ключ админом.
	IsKeyRevoked(ctx context.Context, pubKey string) (bool, error)
}

// IngressController интерфейс, через который сервис дергает ваши ингрессы.
// Нужен для реализации Explicit Eviction (убийства старых сессий).
type IngressController interface {
	// EvictUser принудительно разрывает все активные соединения юзера на указанном протоколе.
	// Например, для AWG это вызовет RemovePeer и ipAlloc.Free.
	EvictUser(ctx context.Context, protocol Protocol, userID string) error
}
