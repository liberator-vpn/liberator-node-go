package transport

import (
	"time"

	"github.com/liberator-vpn/liberator-node-go/internal/utils/dgmessage"
	"github.com/liberator-vpn/liberator-node-go/pkg/model"
	"github.com/liberator-vpn/liberator-node-go/pkg/routingtable"
)

type TransportPeerStats struct {
	VirtualIP     uint32
	DeltaToPeer   uint64
	DeltaFromPeer uint64
	LastSeen      time.Time
}

type Transport interface {
	Run()

	KickPeer(ip uint32) bool
	CreatePeer(peerInfo *model.Peer) error
	ExistsPeer(ip uint32) bool

	GenerateClientConnectionString(peer *model.Peer, addr string, name string) (string, error)
	GeneratePeerKeys(peer *model.Peer) error

	DeltaChan() chan TransportPeerStats
	Type() string
	// Protocols — имена протоколов, которые обслуживает транспорт
	// ("awg", "vless", "hysteria2"). Нода использует их, чтобы направлять
	// сессии из /state в нужный транспорт.
	Protocols() []string
}

type Router interface {
	AddRoutingObject(routingtable.RoutingObject) error
	DeleteRoutingObject(uint32) error

	// GetRemoteRoutingObject нужен транспорту, чтобы проверить, обёрнута ли
	// сессия пира в шейпер (RoutingObject живёт в таблице роутера, а не в
	// транспорте).
	GetRemoteRoutingObject(uint32) (routingtable.RoutingObject, bool)

	NewMessageCopyFrom(data []byte) (*dgmessage.DatagramMessage, error)
	HandleTransportPacket(packet *dgmessage.DatagramMessage)
}
