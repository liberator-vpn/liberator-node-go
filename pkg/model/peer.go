package model

import (
	"time"
)

type Peer struct {
	ID             uint64
	Type           string
	Protocol       string // awg | vless | hysteria2
	Name           string // стабильное имя пользователя (email/tag в xray)
	Auth           string // UUID (VLESS) или пароль (Hysteria2)
	VirtualIP      uint32
	LastSeen       time.Time
	ExpirationDate *time.Time
	FromPeerTotal  uint64
	ToPeerTotal    uint64
	TrafficLimitGb *float64
	SpeedLimitMbps *float64
	AwgPrivateKey  string
	AwgPublicKey   string
}

func (p *Peer) IsExpired() bool {
	if p.ExpirationDate == nil {
		return false
	}
	if time.Now().After(*p.ExpirationDate) {
		return true
	}
	return false
}
