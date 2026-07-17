package vpnauthservice

import (
	"net/netip"
	"time"
)

type Protocol string

const (
	ProtocolQUIC Protocol = "quic"
	ProtocolAWG  Protocol = "awg"
)

// UserLimits описывает ограничения, применяемые к сессии.
type UserLimits struct {
	MaxDownloadBytes int64
	MaxUploadBytes   int64
	MaxSpeedBps      int64
}

// SessionParams то, что передает вызывающий слой (HTTP/gRPC) в сервис.
// Обратите внимание: мы передаем уже распарсенный UserID, сервис не знает про JWT.
type SessionParams struct {
	UserID     string
	Protocol   Protocol
	PublicKey  string // Обязателен для AWG, пустой для QUIC
	DeviceName string
}

// SessionCredentials то, что сервис отдает обратно вызывающему слою для передачи клиенту.
type SessionCredentials struct {
	TicketID   string
	Protocol   Protocol
	ServerIP   string
	ServerPort int
	AssignedIP netip.Addr
	Limits     UserLimits
	TicketTTL  time.Duration

	// Специфичные для AWG
	AWGPrivateKey string
	AWGObfMagic   uint8
	// ... другие параметры обфускации
}

// ValidatedTicket то, что ИНГРЕССЫ получают из сервиса при валидации билета.
type ValidatedTicket struct {
	UserID     string
	AssignedIP netip.Addr
	Protocol   Protocol
	PublicKey  string // Нужно ингрессу AWG для добавления пира
	Limits     UserLimits
}
