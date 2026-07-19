package mesh

type VirtualConnection struct {
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

func (vc *VirtualConnection) SendDatagram(data []byte) error {
	return vc.Parent.peerStore.SendDatagram(vc.NodeID, data)
}
