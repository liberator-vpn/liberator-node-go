package mesh

import (
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
	return vc.Parent.peerStore.SendDatagram(vc.NodeID, data)
}
