package mesh

import "context"

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
	return vc.Parent.peerStore.SendDatagram(vc.NodeID, data)
}
