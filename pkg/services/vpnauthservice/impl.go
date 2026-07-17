package vpnauthservice

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"liberator-node-go/internal/utils/ipalloc"

	"github.com/google/uuid"
)

var (
	ErrUserNotFound  = errors.New("user not found")
	ErrKeyRevoked    = errors.New("key is revoked")
	ErrInvalidTicket = errors.New("invalid or expired ticket")
	ErrNoIPAvailable = errors.New("no ip addresses available")
	ErrLimitExceeded = errors.New("user limits exceeded")
)

type vpnAuthService struct {
	ipAlloc     *ipalloc.IPAllocator
	ticketStore TicketStore
	userRepo    UserRepository
	ingressCtrl IngressController

	ticketTTL   time.Duration
	defaultPort int
	serverIP    string
	awgObfMagic uint8
}

// New создает экземпляр сервиса.
func New(
	ipAlloc *ipalloc.IPAllocator,
	ticketStore TicketStore,
	userRepo UserRepository,
	ingressCtrl IngressController,
	serverIP string,
	defaultPort int,
	awgObfMagic uint8,
) Service {
	return &vpnAuthService{
		ipAlloc:     ipAlloc,
		ticketStore: ticketStore,
		userRepo:    userRepo,
		ingressCtrl: ingressCtrl,
		serverIP:    serverIP,
		defaultPort: defaultPort,
		awgObfMagic: awgObfMagic,
		ticketTTL:   15 * time.Second, // Билет живет 15 секунд
	}
}

func (s *vpnAuthService) CreateSessionByUser(ctx context.Context, params SessionParams) (*SessionCredentials, error) {
	// 1. Проверяем лимиты юзера в БД
	limits, err := s.userRepo.GetUserLimits(ctx, params.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get limits: %w", err)
	}
	if limits.MaxDownloadBytes <= 0 && limits.MaxUploadBytes <= 0 {
		return nil, ErrLimitExceeded
	}

	// 2. ЭВИКЦИЯ: Убиваем старые подключения этого юзера на этом протоколе
	// ВАЖНО: Делаем это ДО выделения нового IP.
	if err := s.ingressCtrl.EvictUser(ctx, params.Protocol, params.UserID); err != nil {
		// Логируем, но не критично, возможно старой сессии не было
		fmt.Printf("warn: failed to evict user %s: %v\n", params.UserID, err)
	}

	// 3. Выделяем IP
	ipNet, err := s.ipAlloc.Get()
	if err != nil {
		return nil, ErrNoIPAvailable
	}
	ipAddr, _ := netip.AddrFromSlice(ipNet)

	// 4. Создаем билет
	ticketID := uuid.New().String()
	validatedData := &ValidatedTicket{
		UserID:     params.UserID,
		AssignedIP: ipAddr,
		Protocol:   params.Protocol,
		PublicKey:  params.PublicKey,
		Limits:     limits,
	}

	if err := s.ticketStore.Set(ctx, ticketID, validatedData, s.ticketTTL); err != nil {
		// Откатываем выделение IP, если не смогли сохранить билет
		s.ipAlloc.Free(ipNet)
		return nil, fmt.Errorf("failed to store ticket: %w", err)
	}

	// 5. Формируем ответ
	creds := &SessionCredentials{
		TicketID:   ticketID,
		Protocol:   params.Protocol,
		ServerIP:   s.serverIP,
		ServerPort: s.defaultPort,
		AssignedIP: ipAddr,
		Limits:     limits,
		TicketTTL:  s.ticketTTL,
	}

	// Если протокол требует отдать клиенту секретные данные (например, сгенерированный на клиенте приватник AWG)
	// В реальности приватник генерирует клиент, здесь мы просто прокидываем его дальше или заполняем параметры обфускации
	if params.Protocol == ProtocolAWG {
		creds.AWGObfMagic = s.awgObfMagic
		// В реальном приложении здесь может быть логика генерации параметров обфускации,
		// если они уникальны для каждой сессии, а не глобальные для сервера.
	}

	return creds, nil
}

func (s *vpnAuthService) CreateSessionByKey(ctx context.Context, pubKey string, protocol Protocol) (*SessionCredentials, error) {
	// 1. Проверяем ключ в БД
	revoked, err := s.userRepo.IsKeyRevoked(ctx, pubKey)
	if err != nil {
		return nil, fmt.Errorf("db error: %w", err)
	}
	if revoked {
		return nil, ErrKeyRevoked
	}

	// 2. Ищем юзера (может быть пустым, если ключ полностью анонимный)
	userID, err := s.userRepo.FindUserIDByPublicKey(ctx, pubKey)
	if err != nil {
		return nil, ErrUserNotFound
	}

	// 3. Переиспользуем основную логику
	return s.CreateSessionByUser(ctx, SessionParams{
		UserID:    userID,
		Protocol:  protocol,
		PublicKey: pubKey,
	})
}

func (s *vpnAuthService) ValidateTicket(ctx context.Context, ticketID string) (*ValidatedTicket, error) {
	// GetAndDelete атомарно забирает билет. Второй раз по этому ID ингресс не пройдет.
	ticket, err := s.ticketStore.GetAndDelete(ctx, ticketID)
	if err != nil {
		return nil, ErrInvalidTicket
	}
	return ticket, nil
}

func (s *vpnAuthService) TerminateSession(ctx context.Context, ticketID string) error {
	// Для корректного завершения по желанию юзера, нам нужно узнать, какому юзеру принадлежал билет.
	// Так как билет уже мог быть использован (удален из Redis), нам нужен отдельный механизм.
	// Обычно на стороне ингрессов хранится мапа: TicketID -> UserID/SessionInfo
	// Ингресс сам вызывает ipAlloc.Free() при отключении.

	// Упрощенная реализация: ингресс должен сам обработать дисконнект,
	// а этот метод в сервисе может просто сбросить кэш лимитов юзера, если нужно.
	return nil
}
