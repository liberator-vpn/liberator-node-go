package mesh

import (
	"context"
	"fmt"
)

type VirtualConnection struct {
	Ctx       context.Context
	Parent    *MeshNode
	NodeID    string
	VirtualIp uint32
}

func (vc *VirtualConnection) GetNodeID() string {
	return vc.NodeID
}
func (vc *VirtualConnection) GetVirtualIP() uint32 {
	return vc.VirtualIp
}
func (vc *VirtualConnection) Context() context.Context {
	return vc.Ctx
}

func (vc *VirtualConnection) SendDatagram(data []byte) error {
	conn, ex := vc.Parent.peerStore.Get(vc.NodeID)
	if !ex {
		return fmt.Errorf("not found")
	}
	return conn.Connection.SendDatagram(data)
}
