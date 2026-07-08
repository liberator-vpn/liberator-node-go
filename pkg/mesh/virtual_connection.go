package mesh

import (
	"fmt"
	"net"

	"github.com/google/uuid"
)

type VirtualConnection struct {
	Parent    *MeshNode
	NodeID    string
	UserID    uuid.UUID
	VirtualIp net.IP
}

func (vc *VirtualConnection) GetNodeID() string {
	return vc.NodeID
}
func (vc *VirtualConnection) GetUserID() uuid.UUID {
	return vc.UserID
}
func (vc *VirtualConnection) GetVirtualIP() net.IP {
	return vc.VirtualIp
}

func (vc *VirtualConnection) SendDatagram(data []byte) error {
	peer, ex := vc.Parent.peerStore.Get(vc.NodeID)
	if !ex {
		return fmt.Errorf("peer not found")
	}
	return peer.Connection.SendDatagram(data)
}
