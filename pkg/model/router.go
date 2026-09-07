package model

type RouterStats struct {
	TotalFromIface uint64 `json:"from_iface"`
	TotalFromMesh  uint64 `json:"from_mesh"`
	TotalFromPeers uint64 `json:"from_peers"`
}
