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

	IsAllowedUsers(u1, u2 uuid.UUID) bool
	IsAllowedIps(u1, u2 net.IP) bool

	Allow(u1, u2 uuid.UUID)
}

type routingTableImpl struct {
	byUserID    map[uuid.UUID]RoutingObject
	byVirtualIp map[string]RoutingObject

	userAllowMap map[uuid.UUID]map[uuid.UUID]struct{}

	updateLock sync.RWMutex
}

func New() RoutingTable {
	return &routingTableImpl{
		byUserID:     map[uuid.UUID]RoutingObject{},
		byVirtualIp:  map[string]RoutingObject{},
		userAllowMap: make(map[uuid.UUID]map[uuid.UUID]struct{}),
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

// INTERCONNECTIONS

func (r *routingTableImpl) IsAllowedUsers(u1, u2 uuid.UUID) bool {
	r.updateLock.RLock()
	defer r.updateLock.RUnlock()

	if peers, ok := r.userAllowMap[u1]; ok {
		if _, exists := peers[u2]; exists {
			return true
		}
	}
	return false
}

func (r *routingTableImpl) Allow(u1, u2 uuid.UUID) {
	if u1 == u2 {
		return
	}

	r.updateLock.Lock()
	defer r.updateLock.Unlock()

	// Инициализируем множество для u1, если его нет
	if r.userAllowMap[u1] == nil {
		r.userAllowMap[u1] = make(map[uuid.UUID]struct{})
	}
	r.userAllowMap[u1][u2] = struct{}{}

	// Инициализируем множество для u2, если его нет
	if r.userAllowMap[u2] == nil {
		r.userAllowMap[u2] = make(map[uuid.UUID]struct{})
	}
	r.userAllowMap[u2][u1] = struct{}{}
}

func (r *routingTableImpl) IsAllowedIps(u1, u2 net.IP) bool {
	r.updateLock.RLock()
	defer r.updateLock.RUnlock()

	obj1, ex := r.byVirtualIp[u1.String()]
	if !ex {
		return false
	}
	obj2, ex := r.byVirtualIp[u2.String()]
	if !ex {
		return false
	}

	return r.IsAllowedUsers(obj1.GetUserID(), obj2.GetUserID())
}
