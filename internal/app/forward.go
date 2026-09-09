package app

import (
	"context"

	"github.com/liberator-vpn/liberator-node-go/internal/apiclient"
	"github.com/liberator-vpn/liberator-node-go/internal/utils/netutils"
	"github.com/liberator-vpn/liberator-node-go/pkg/firewall"
)

// reconcileRemotes собирает из глобальной директории клиентов желаемый набор
// remote-клиентов (virtual IP -> mesh endpoint владеющей ноды) и отдаёт его mesh,
// который держит их и обновляет routing-таблицу роутера.
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

	app.node.ReconcileRemoteClients(desired)
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
