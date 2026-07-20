package router

import (
	"github.com/TexHik620953/liberator-node-go/internal/utils/dgmessage"
	"github.com/TexHik620953/liberator-node-go/pkg/routingtable"
)

// Agregated packets pool and routing table
func (r *Router) NewMessageCopyFrom(data []byte) (*dgmessage.DatagramMessage, error) {
	return r.packetsPool.NewMessageCopyFrom(data)
}
func (r *Router) AddRoutingObject(obj routingtable.RoutingObject) error {
	return r.routingTable.Add(obj)
}
func (r *Router) DeleteRoutingObject(obj routingtable.RoutingObject) error {
	return r.routingTable.Delete(obj)
}

// For TUN interface
func (r *Router) ToTUNChannel() chan *dgmessage.DatagramMessage {
	return r.toIface
}
