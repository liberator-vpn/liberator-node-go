package router

import (
	"github.com/TexHik620953/liberator-node-go/pkg/firewall"
)

func (r *Router) AddRule(index firewall.PortRuleIndex, rule firewall.PortRule) bool {
	ok := r.firewall.AddRule(index, rule)
	if !ok {
		return false
	}

	r.notifyFirewallEvent(FirewallEvent{
		Type:   FirewallEventType_RuleAdded,
		NodeID: index.NodeID,
		RuleID: index.RuleID,

		Address:        rule.Address,
		TargetAddress:  rule.TargetAddress,
		Protocol:       rule.Protocol,
		PortRangeStart: rule.PortRangeStart,
		PortRangeEnd:   rule.PortRangeEnd,
	})
	return true
}
func (r *Router) DumpRules() []firewall.RuleDump {
	return r.firewall.DumpRules()
}
func (r *Router) RemoveRule(index firewall.PortRuleIndex) bool {
	ok := r.firewall.RemoveRule(index)
	if !ok {
		return false
	}

	r.notifyFirewallEvent(FirewallEvent{
		Type:   FirewallEventType_RuleRemoved,
		NodeID: index.NodeID,
		RuleID: index.RuleID,
	})
	return true
}

func (r *Router) ExistsRule(index firewall.PortRuleIndex) bool {
	return r.firewall.ExistsRule(index)
}

// Does not fire events
func (r *Router) AddRemoteRule(index firewall.PortRuleIndex, rule firewall.PortRule) bool {
	return r.firewall.AddRule(index, rule)
}
func (r *Router) RemoveRemoteRule(index firewall.PortRuleIndex) bool {
	return r.firewall.RemoveRule(index)
}
