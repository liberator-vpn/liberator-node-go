package mesh

import (
	"liberator-node-go/internal/utils/dgmessage"
	"liberator-node-go/pkg/routingtable"
)

type Router interface {
	AddRoutingObject(routingtable.RoutingObject) error
	DeleteRoutingObject(routingtable.RoutingObject) error

	NewMessageCopyFrom(data []byte) (*dgmessage.DatagramMessage, error)
	HandleMeshPacket(packet *dgmessage.DatagramMessage)
}
