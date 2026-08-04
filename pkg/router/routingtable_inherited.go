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
	err := r.routingTable.Add(obj)
	if err != nil {
		return err
	}
	r.notifyRoutingEvent(RouterEvent{
		Type:      RouterEventType_ClientAdded,
		VirtualIP: obj.GetVirtualIP(),
		NodeID:    obj.GetNodeID(),
	})
	return nil
}

func (r *Router) DumpRoutingTable() []routingtable.RoutingTableRecordDump {
	return r.routingTable.Dump()
}

func (r *Router) DeleteRoutingObject(ip uint32) error {
	obj, ex := r.routingTable.GetByIP(ip)
	if !ex {
		return nil
	}
	nodeID := obj.GetNodeID()

	err := r.routingTable.Delete(ip)
	if err != nil {
		return err
	}

	r.notifyRoutingEvent(RouterEvent{
		Type:      RouterEventType_ClientRemoved,
		VirtualIP: ip,
		NodeID:    nodeID,
	})
	return nil
}

// Remote, does not fire events
func (r *Router) AddRemoteRoutingObject(obj routingtable.RoutingObject) error {
	err := r.routingTable.Add(obj)
	if err != nil {
		return err
	}
	return nil
}
func (r *Router) DeleteRemoteRoutingObject(ip uint32) error {
	err := r.routingTable.Delete(ip)
	if err != nil {
		return err
	}
	return nil
}
func (r *Router) GetRemoteRoutingObject(ip uint32) (routingtable.RoutingObject, bool) {
	obj, ex := r.routingTable.GetByIP(ip)
	return obj, ex
}

// For TUN interface
func (r *Router) ToTUNChannel() chan *dgmessage.DatagramMessage {
	return r.toIface
}
