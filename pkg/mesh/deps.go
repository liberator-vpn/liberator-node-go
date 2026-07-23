package mesh

import (
	"github.com/TexHik620953/liberator-node-go/internal/utils/dgmessage"
	"github.com/TexHik620953/liberator-node-go/pkg/routingtable"
)

type Router interface {
	AddRoutingObject(routingtable.RoutingObject) error
	DeleteRoutingObject(uint32) error

	NewMessageCopyFrom(data []byte) (*dgmessage.DatagramMessage, error)
	HandleMeshPacket(packet *dgmessage.DatagramMessage)
}
