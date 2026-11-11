package mesh

import (
	"context"

	"github.com/liberator-vpn/liberator-node-go/pkg/routingtable"
)

// RemoteClient — routing-объект для клиента другой ноды (client→client):
// его SendDatagram пересылает пакет на владеющую ноду через mesh.SendTo.
type RemoteClient struct {
	ctx  context.Context
	ip   uint32
	send func([]byte) error
}

func (r *RemoteClient) GetNodeID() string    { return "" }
func (r *RemoteClient) GetVirtualIP() uint32 { return r.ip }
func (r *RemoteClient) Context() context.Context {
	return r.ctx
}
func (r *RemoteClient) SendDatagram(data []byte) error { return r.send(data) }

// SetRemoteRouting регистрирует, куда mesh должен добавлять/удалять remote-объекты
// (это методы routing-таблицы роутера), вызывается из app при старте.
func (n *MeshNode) SetRemoteRouting(
	add func(routingtable.RoutingObject) error,
	del func(uint32) error,
) {
	n.remoteMu.Lock()
	n.addRemoteObj = add
	n.delRemoteObj = del
	n.remoteMu.Unlock()
}

// ReconcileRemoteClients приводит таблицу remote-клиентов (virtual IP -> mesh
// endpoint владеющей ноды) в соответствие желаемому набору, обновляя routing-таблицу.
func (n *MeshNode) ReconcileRemoteClients(desired map[uint32]string) {
	n.remoteMu.Lock()
	defer n.remoteMu.Unlock()

	for ip, endpoint := range desired {
		if n.remotes[ip] == endpoint {
			continue
		}
		if _, existed := n.remotes[ip]; existed {
			n.removeRemote(ip)
		}
		if n.addRemote(ip, endpoint) {
			n.remotes[ip] = endpoint
		} else {
			// Не запоминаем неудачную установку: иначе следующая попытка
			// будет пропущена как «уже применено» и маршрут останется дырой.
			delete(n.remotes, ip)
		}
	}

	for ip := range n.remotes {
		if _, keep := desired[ip]; !keep {
			n.removeRemote(ip)
			delete(n.remotes, ip)
		}
	}
}

func (n *MeshNode) addRemote(ip uint32, endpoint string) bool {
	if n.addRemoteObj == nil {
		return false
	}
	obj := &RemoteClient{ctx: n.ctx, ip: ip}
	obj.send = func(data []byte) error {
		return n.SendTo(n.ctx, endpoint, data)
	}
	return n.addRemoteObj(obj) == nil
}

func (n *MeshNode) removeRemote(ip uint32) {
	if n.delRemoteObj != nil {
		_ = n.delRemoteObj(ip)
	}
}

var _ routingtable.RoutingObject = (*RemoteClient)(nil)
