package transport

import (
	"time"

	"github.com/TexHik620953/liberator-node-go/internal/utils/dgmessage"
	"github.com/TexHik620953/liberator-node-go/pkg/model"
	"github.com/TexHik620953/liberator-node-go/pkg/routingtable"
)

type TransportPeerStats struct {
	VirtualIP     uint32
	DeltaToPeer   uint64
	DeltaFromPeer uint64
	LastSeen      time.Time
}

type Transport interface {
	Run()

	KickUser(ip uint32) bool
	PreparePeer(peerInfo *model.Peer) error

	GenerateClientConnectionString(peer *model.Peer, addr string, name string) (string, error)
	GeneratePeerKeys(peer *model.Peer) error

	DeltaChan() chan TransportPeerStats
	Type() string
}

type Router interface {
	AddRoutingObject(routingtable.RoutingObject) error
	DeleteRoutingObject(routingtable.RoutingObject) error

	NewMessageCopyFrom(data []byte) (*dgmessage.DatagramMessage, error)
	HandleTransportPacket(packet *dgmessage.DatagramMessage)
}
