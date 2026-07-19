package transport

import (
	"liberator-node-go/internal/utils/dgmessage"
	"liberator-node-go/pkg/routingtable"
	"time"
)

type Transport interface {
	Run()

	KickUser(ip uint32) bool
	PreparePeer(ip uint32, publicKeyHex string, timeout time.Duration) error
}

type Router interface {
	AddRoutingObject(routingtable.RoutingObject) error
	DeleteRoutingObject(routingtable.RoutingObject) error

	NewMessageCopyFrom(data []byte) (*dgmessage.DatagramMessage, error)
	HandleTransportPacket(packet *dgmessage.DatagramMessage)
}
