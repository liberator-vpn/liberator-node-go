package model

import (
	"time"
)

type Peer struct {
	ID             uint64
	Type           string
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
		return true
	}
	if time.Now().After(*p.ExpirationDate) {
		return true
	}
	return false
}
