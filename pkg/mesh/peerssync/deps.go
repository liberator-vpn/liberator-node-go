package peerssync

import (
	"context"

	"github.com/TexHik620953/liberator-node-go/pkg/firewall"
	"github.com/TexHik620953/liberator-node-go/pkg/router"
	"github.com/TexHik620953/liberator-node-go/pkg/routingtable"
)

type Router interface {
	SubscribeFirewallEvents(ctx context.Context) (<-chan router.FirewallEvent, context.CancelFunc)
	DumpRules() []firewall.RuleDump
	AddRemoteRule(index firewall.PortRuleIndex, rule firewall.PortRule) bool
	RemoveRemoteRule(index firewall.PortRuleIndex) bool
	ExistsRule(index firewall.PortRuleIndex) bool

	SubscribeRoutingEvents(ctx context.Context) (<-chan router.RouterEvent, context.CancelFunc)
	DumpRoutingTable() []routingtable.RoutingTableRecordDump
	AddRemoteRoutingObject(obj routingtable.RoutingObject) error
	DeleteRemoteRoutingObject(ip uint32) error
	GetRemoteRoutingObject(ip uint32) (routingtable.RoutingObject, bool)
}
