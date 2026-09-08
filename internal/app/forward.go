package app

import (
	"context"

	"github.com/liberator-vpn/liberator-node-go/internal/apiclient"
	"github.com/liberator-vpn/liberator-node-go/internal/utils/netutils"
	"github.com/liberator-vpn/liberator-node-go/pkg/firewall"
)

// remoteClient — routing-объект для чужого клиента: отправляет датаграмму на
// владеющую ноду через mesh по её mesh_endpoint.
type remoteClient struct {
	ctx    context.Context
	ip     uint32
	nodeID string
	send   func([]byte) error
}

func (r *remoteClient) GetNodeID() string    { return r.nodeID }
func (r *remoteClient) GetVirtualIP() uint32 { return r.ip }
func (r *remoteClient) Context() context.Context {
	return r.ctx
}
func (r *remoteClient) SendDatagram(data []byte) error { return r.send(data) }

// reconcileRemotes поддерживает в роутере маршруты к клиентам других нод
// (client→client) по глобальной директории /v1/ctrl/clients.
func (app *App) reconcileRemotes(ctx context.Context, client *apiclient.Client, nodeID string) {
	cl, err := client.GetClients(ctx, nodeID)
	if err != nil {
		return
	}

	desired := make(map[uint32]string, len(cl.Clients))
	for _, c := range cl.Clients {
		if c.Node.ID == "" || c.Node.ID == nodeID {
			continue // локальные клиенты провижиним из /state
		}
		if c.Node.MeshEndpoint == "" || c.PeerIP == "" {
			continue
		}
		ip := netutils.IPStringToUint32(c.PeerIP)
		if ip == 0 {
			continue
		}
		desired[ip] = c.Node.MeshEndpoint
	}

	for ip, endpoint := range desired {
		if app.remotes[ip] == endpoint {
			continue
		}
		endpoint := endpoint
		obj := &remoteClient{
			ctx:    app.ctx,
			ip:     ip,
			nodeID: ownerOf(cl, ip),
			send: func(data []byte) error {
				return app.node.SendTo(app.ctx, endpoint, data)
			},
		}
		if err := app.router.AddRemoteRoutingObject(obj); err != nil {
			// возможно, IP уже занят локальным клиентом — пропускаем
			continue
		}
		app.remotes[ip] = endpoint
	}

	for ip := range app.remotes {
		if _, keep := desired[ip]; keep {
			continue
		}
		_ = app.router.DeleteRemoteRoutingObject(ip)
		delete(app.remotes, ip)
	}
}

func ownerOf(cl *apiclient.ClientsResult, ip uint32) string {
	for _, c := range cl.Clients {
		if netutils.IPStringToUint32(c.PeerIP) == ip {
			return c.Node.ID
		}
	}
	return ""
}

// applyFirewallPairs ставит/снимает разрешённые client→client потоки
// (recipient<-sender), которые эта нода должна разрешать как источник.
func (app *App) applyFirewallPairs(pairs []apiclient.FirewallPair) {
	desired := make(map[uint64]struct{}, len(pairs))
	for _, p := range pairs {
		rec := netutils.IPStringToUint32(p.RecipientIP)
		snd := netutils.IPStringToUint32(p.SenderIP)
		if rec == 0 || snd == 0 {
			continue
		}
		id := pairRuleID(rec, snd)
		desired[id] = struct{}{}
		if _, ok := app.fwRules[id]; ok {
			continue
		}
		app.router.AddRule(firewall.PortRuleIndex{NodeID: app.nodeID, RuleID: id},
			firewall.PortRule{
				Address:       rec,
				TargetAddress: &snd,
				Protocol:      "both",
			})
		app.fwRules[id] = struct{}{}
	}

	for id := range app.fwRules {
		if _, keep := desired[id]; keep {
			continue
		}
		app.router.RemoveRule(firewall.PortRuleIndex{NodeID: app.nodeID, RuleID: id})
		delete(app.fwRules, id)
	}
}

// pairRuleID даёт стабильный RuleID для пары (recipient, sender).
func pairRuleID(rec, snd uint32) uint64 {
	return uint64(rec)<<32 | uint64(snd)
}
