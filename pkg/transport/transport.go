package transport

import (
	"liberator-node-go/internal/utils/dgmessage"
	"liberator-node-go/pkg/model"
	"liberator-node-go/pkg/routingtable"
)

type Transport interface {
	Run()

	KickUser(ip uint32) bool
	PreparePeer(peerInfo *model.Peer) error
}

type Router interface {
	AddRoutingObject(routingtable.RoutingObject) error
	DeleteRoutingObject(routingtable.RoutingObject) error

	NewMessageCopyFrom(data []byte) (*dgmessage.DatagramMessage, error)
	HandleTransportPacket(packet *dgmessage.DatagramMessage)
}
