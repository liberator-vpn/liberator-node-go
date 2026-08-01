package mesh

import "github.com/TexHik620953/liberator-node-go/pkg/model"

func (n *MeshNode) GetConnectivity() []model.ConnectivityState {
	result := make([]model.ConnectivityState, 0)
	for _, sess := range n.registry.ListActive() {
		result = append(result, model.ConnectivityState{
			Id:        sess.PeerID,
			Addr:      sess.Conn.RemoteAddr().String(),
			TotalSent: sess.Conn.TotalSent(),
			TotalRecv: sess.Conn.TotalRecv(),
		})
	}
	return result
}
