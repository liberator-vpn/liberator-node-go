package peerssync

import (
	"context"
	"testing"

	"github.com/TexHik620953/liberator-node-go/pkg/firewall"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/peerssync/proto"
	"github.com/TexHik620953/liberator-node-go/pkg/router"
	"github.com/TexHik620953/liberator-node-go/pkg/routingtable"
)

// Роутер в памяти: syncRules/syncClients трогают только правила и таблицу маршрутизации.
type fakeRouter struct {
	rules  map[firewall.PortRuleIndex]struct{}
	routes map[uint32]routingtable.RoutingObject
}

func newFakeRouter() *fakeRouter {
	return &fakeRouter{
		rules:  make(map[firewall.PortRuleIndex]struct{}),
		routes: make(map[uint32]routingtable.RoutingObject),
	}
}

func (r *fakeRouter) DumpRules() []firewall.RuleDump {
	dump := make([]firewall.RuleDump, 0, len(r.rules))
	for idx := range r.rules {
		dump = append(dump, firewall.RuleDump{NodeID: idx.NodeID, RuleID: idx.RuleID})
	}
	return dump
}

func (r *fakeRouter) ExistsRule(index firewall.PortRuleIndex) bool {
	_, ok := r.rules[index]
	return ok
}

func (r *fakeRouter) AddRemoteRule(index firewall.PortRuleIndex, _ firewall.PortRule) bool {
	r.rules[index] = struct{}{}
	return true
}

func (r *fakeRouter) RemoveRemoteRule(index firewall.PortRuleIndex) bool {
	_, ok := r.rules[index]
	delete(r.rules, index)
	return ok
}

func (r *fakeRouter) DumpRoutingTable() []routingtable.RoutingTableRecordDump {
	dump := make([]routingtable.RoutingTableRecordDump, 0, len(r.routes))
	for ip, obj := range r.routes {
		dump = append(dump, routingtable.RoutingTableRecordDump{NodeID: obj.GetNodeID(), VirtualIP: ip})
	}
	return dump
}

func (r *fakeRouter) AddRemoteRoutingObject(obj routingtable.RoutingObject) error {
	r.routes[obj.GetVirtualIP()] = obj
	return nil
}

func (r *fakeRouter) DeleteRemoteRoutingObject(ip uint32) error {
	delete(r.routes, ip)
	return nil
}

func (r *fakeRouter) GetRemoteRoutingObject(ip uint32) (routingtable.RoutingObject, bool) {
	obj, ok := r.routes[ip]
	return obj, ok
}

func (r *fakeRouter) SubscribeFirewallEvents(context.Context) (<-chan router.FirewallEvent, context.CancelFunc) {
	return nil, func() {}
}

func (r *fakeRouter) SubscribeRoutingEvents(context.Context) (<-chan router.RouterEvent, context.CancelFunc) {
	return nil, func() {}
}

const (
	localNode = "local"
	peerNode  = "peer"
	thirdNode = "third"
)

func newTestSyncer(r *fakeRouter) *PeersSyncSyncer {
	return NewPeersSyncSyncer(context.Background(), nil, r, localNode, make(chan RemoteMessage, 1))
}

func TestSyncRulesReconcilesPeerRulesOnly(t *testing.T) {
	r := newFakeRouter()
	r.rules[firewall.PortRuleIndex{NodeID: peerNode, RuleID: 1}] = struct{}{}  // пир его удалил
	r.rules[firewall.PortRuleIndex{NodeID: thirdNode, RuleID: 1}] = struct{}{} // пир о нем не знает
	r.rules[firewall.PortRuleIndex{NodeID: localNode, RuleID: 1}] = struct{}{} // наше собственное

	newTestSyncer(r).syncRules(peerNode, []*proto.ClientRule{
		{NodeId: peerNode, Id: 2},
		// Устаревший дамп: пир все еще помнит удаленное нами правило и чужое правило.
		{NodeId: localNode, Id: 7},
		{NodeId: thirdNode, Id: 2},
	})

	want := map[firewall.PortRuleIndex]bool{
		{NodeID: peerNode, RuleID: 2}:  true, // добавлено из дампа
		{NodeID: thirdNode, RuleID: 1}: true, // чужое правило не наша забота
		{NodeID: thirdNode, RuleID: 2}: true, // но новое чужое подхватываем
		{NodeID: localNode, RuleID: 1}: true, // свое не трогаем
	}
	for idx := range r.rules {
		if !want[idx] {
			t.Fatalf("unexpected rule left: %+v", idx)
		}
		delete(want, idx)
	}
	for idx := range want {
		t.Fatalf("rule missing: %+v", idx)
	}
}

func TestSyncClientsReconcilesPeerClientsOnly(t *testing.T) {
	r := newFakeRouter()
	local := newRemoteClient(context.Background(), 10, localNode, nil)
	r.routes[10] = local                                                    // наш собственный клиент
	r.routes[20] = newRemoteClient(context.Background(), 20, peerNode, nil) // пир его уже отцепил
	r.routes[30] = newRemoteClient(context.Background(), 30, thirdNode, nil)

	newTestSyncer(r).syncClients(peerNode, []*proto.ClientInfo{
		{NodeId: peerNode, VirtualIp: 21},
		// Пир считает, что наш клиент 10 переехал к нему — верить нельзя.
		{NodeId: peerNode, VirtualIp: 10},
	})

	if r.routes[10] != local {
		t.Fatal("local client must not be stolen by a peer dump")
	}
	if _, ok := r.routes[20]; ok {
		t.Fatal("client dropped by the peer must be removed")
	}
	if _, ok := r.routes[30]; !ok {
		t.Fatal("third node client must survive")
	}
	if _, ok := r.routes[21]; !ok {
		t.Fatal("new peer client must be added")
	}
}
