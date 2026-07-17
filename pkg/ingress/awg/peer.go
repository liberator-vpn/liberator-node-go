package awg

import (
	"net"
	"time"

	"github.com/google/uuid"
)

// ---------------------------------------------------------
// 1. Абстракция пира (Аналог IngressConnection в QUIC)
// ---------------------------------------------------------

type AWGPeer struct {
	id        string
	nodeID    string
	userID    uuid.UUID
	virtualIP net.IP
	pubKey    string
	lastSeen  time.Time
	ingress   *Ingress
}

func NewAWGPeer(nodeID string, userID uuid.UUID, ip net.IP, pubKey string, ingress *Ingress) *AWGPeer {
	return &AWGPeer{
		id:        uuid.NewString(),
		nodeID:    nodeID,
		userID:    userID,
		virtualIP: ip,
		pubKey:    pubKey,
		lastSeen:  time.Now(),
		ingress:   ingress,
	}
}

// --- Реализация интерфейса routingtable.RoutingObject ---

func (p *AWGPeer) GetNodeID() string    { return p.nodeID }
func (p *AWGPeer) GetUserID() uuid.UUID { return p.userID }
func (p *AWGPeer) GetVirtualIP() net.IP { return p.virtualIP }

func (p *AWGPeer) SendDatagram(data []byte) error {
	return p.ingress.writePacket(data)
}

func (p *AWGPeer) Close() {
	// Для AWG физическое закрытие происходит через удаление пира из ядра
}
