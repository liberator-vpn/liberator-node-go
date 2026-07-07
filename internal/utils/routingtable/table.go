package routingtable

import (
	"fmt"
	"net"
	"sync"

	"github.com/google/uuid"
)

type RoutingObject interface {
	GetUserID() uuid.UUID
	GetVirtualIP() net.IP

	SendDatagram(data []byte) error
}

type RoutingTable interface {
	Add(RoutingObject) error
	Delete(RoutingObject) error

	GetByUserID(uuid.UUID) (RoutingObject, bool)
	GetByVirtualIp(net.IP) (RoutingObject, bool)
}

type routingTableImpl struct {
	byUserID    map[uuid.UUID]RoutingObject
	byVirtualIp map[string]RoutingObject

	updateLock sync.RWMutex
}

func New() RoutingTable {
	return &routingTableImpl{
		byUserID:    map[uuid.UUID]RoutingObject{},
		byVirtualIp: map[string]RoutingObject{},
	}
}

// Add implements [RoutingTable].
func (r *routingTableImpl) Add(obj RoutingObject) error {
	r.updateLock.Lock()
	defer r.updateLock.Unlock()

	// Check if partially exist
	_, idEx := r.byUserID[obj.GetUserID()]
	_, ipEx := r.byVirtualIp[obj.GetVirtualIP().String()]
	if idEx != ipEx {
		return fmt.Errorf("failed to add partially existing routing object")
	}

	r.byUserID[obj.GetUserID()] = obj
	r.byVirtualIp[obj.GetVirtualIP().String()] = obj
	return nil
}

// Delete implements [RoutingTable].
func (r *routingTableImpl) Delete(obj RoutingObject) error {
	r.updateLock.Lock()
	defer r.updateLock.Unlock()

	// Check if partially exist
	_, idEx := r.byUserID[obj.GetUserID()]
	_, ipEx := r.byVirtualIp[obj.GetVirtualIP().String()]
	if idEx != ipEx {
		return fmt.Errorf("failed to add partially existing routing object")
	}

	delete(r.byUserID, obj.GetUserID())
	delete(r.byVirtualIp, obj.GetVirtualIP().String())

	return nil
}

// GetByUserID implements [RoutingTable].
func (r *routingTableImpl) GetByUserID(id uuid.UUID) (RoutingObject, bool) {
	r.updateLock.RLock()
	defer r.updateLock.RUnlock()
	obj, ex := r.byUserID[id]
	return obj, ex
}

// GetByVirtualIp implements [RoutingTable].
func (r *routingTableImpl) GetByVirtualIp(ip net.IP) (RoutingObject, bool) {
	r.updateLock.RLock()
	defer r.updateLock.RUnlock()
	obj, ex := r.byVirtualIp[ip.String()]
	return obj, ex
}
