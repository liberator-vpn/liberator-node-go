package routingtable

import (
	"fmt"
	"sync"
)

type RoutingTableRecordDump struct {
	NodeID    string
	VirtualIP uint32
}

type RoutingObject interface {
	GetNodeID() string
	GetVirtualIP() uint32
	SendDatagram([]byte) error
}

type RoutingTable interface {
	Add(RoutingObject) error
	Delete(RoutingObject) error

	GetByIP(uint32) (RoutingObject, bool)
	Dump() []RoutingTableRecordDump
}

type routingTableImpl struct {
	byVirtualIp map[uint32]RoutingObject
	updateLock  sync.RWMutex
}

func New() RoutingTable {
	return &routingTableImpl{
		byVirtualIp: map[uint32]RoutingObject{},
	}
}

// Add implements [RoutingTable].
func (r *routingTableImpl) Add(obj RoutingObject) error {
	r.updateLock.Lock()
	defer r.updateLock.Unlock()

	_, ipEx := r.byVirtualIp[obj.GetVirtualIP()]
	if ipEx {
		return fmt.Errorf("record for ip %d already exists", obj.GetVirtualIP())
	}
	r.byVirtualIp[obj.GetVirtualIP()] = obj
	return nil
}

// Delete implements [RoutingTable].
func (r *routingTableImpl) Delete(obj RoutingObject) error {
	r.updateLock.Lock()
	defer r.updateLock.Unlock()

	_, ipEx := r.byVirtualIp[obj.GetVirtualIP()]

	if !ipEx {
		return nil
	}
	delete(r.byVirtualIp, obj.GetVirtualIP())
	return nil
}

// GetByVirtualIp implements [RoutingTable].
func (r *routingTableImpl) GetByIP(ip uint32) (RoutingObject, bool) {
	r.updateLock.RLock()
	defer r.updateLock.RUnlock()
	obj, ex := r.byVirtualIp[ip]
	return obj, ex
}

func (r *routingTableImpl) Dump() []RoutingTableRecordDump {
	r.updateLock.Lock()
	defer r.updateLock.Unlock()
	dump := make([]RoutingTableRecordDump, 0, len(r.byVirtualIp))
	for _, v := range r.byVirtualIp {
		record := RoutingTableRecordDump{
			VirtualIP: v.GetVirtualIP(),
			NodeID:    v.GetNodeID(),
		}
		dump = append(dump, record)
	}
	return dump
}
