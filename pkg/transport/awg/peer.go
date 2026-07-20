package awg

import (
	"time"
)

// ---------------------------------------------------------
// 1. Абстракция пира (Аналог IngressConnection в QUIC)
// ---------------------------------------------------------

type AWGPeer struct {
	nodeID     string
	virtualIP  uint32
	pubKey     string
	lastSeen   time.Time
	ingress    *AWGTransport
	expiration *time.Time
}

func NewAWGPeer(nodeID string, ip uint32, pubKey string, ingress *AWGTransport, expiration *time.Time) *AWGPeer {
	return &AWGPeer{
		nodeID:     nodeID,
		virtualIP:  ip,
		pubKey:     pubKey,
		lastSeen:   time.Now(),
		ingress:    ingress,
		expiration: expiration,
	}
}

// --- Реализация интерфейса routingtable.RoutingObject ---

func (p *AWGPeer) GetNodeID() string    { return p.nodeID }
func (p *AWGPeer) GetVirtualIP() uint32 { return p.virtualIP }

func (p *AWGPeer) SendDatagram(data []byte) error {
	return p.ingress.writePacket(data)
}

func (p *AWGPeer) Close() {
	// Для AWG физическое закрытие происходит через удаление пира из ядра
}
