package vpnauthservice

import (
	"context"
)

// Service содержит бизнес-логику авторизации и выдачи доступов к VPN.
type Service interface {
	// CreateSessionByUser создает сессию для авторизованного юзера (по JWT).
	CreateSessionByUser(ctx context.Context, params SessionParams) (*SessionCredentials, error)

	// CreateSessionByKey создает сессию по персистентному ключу (без JWT).
	CreateSessionByKey(ctx context.Context, pubKey string, protocol Protocol) (*SessionCredentials, error)

	// ValidateTicket вызывается ингрессами при подключении клиента.
	// Проверяет билет, удаляет его (одноразовость) и возвращает данные для поднятия туннеля.
	ValidateTicket(ctx context.Context, ticketID string) (*ValidatedTicket, error)

	// TerminateSession явный разрыв сессии (когда юзер нажимает "Отключиться").
	TerminateSession(ctx context.Context, ticketID string) error
}
