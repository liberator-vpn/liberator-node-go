package app

import (
	"context"
	"testing"

	"github.com/liberator-vpn/liberator-node-go/internal/apiclient"
	"github.com/liberator-vpn/liberator-node-go/pkg/router"
)

// applyFirewallPairs обязан ставить правило на весь диапазон портов:
// пара из API не содержит порт, а nil PortRangeEnd матчил только dstPort=0.
func TestApplyFirewallPairsUsesFullPortRange(t *testing.T) {
	r, err := router.New(context.Background(), "10.0.0.1", "10.0.0.0/8")
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	a := &App{
		router:  r,
		nodeID:  "node",
		fwRules: make(map[uint64]struct{}),
	}

	a.applyFirewallPairs([]apiclient.FirewallPair{{
		RecipientIP: "10.0.0.5",
		SenderIP:    "10.0.0.2",
	}})

	rules := r.DumpRules()
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	rule := rules[0]
	if rule.PortRangeEnd == nil || rule.PortRangeStart != 0 || *rule.PortRangeEnd != 65535 {
		t.Fatalf("port range = %d..%v, want 0..65535", rule.PortRangeStart, rule.PortRangeEnd)
	}

	// Удаление из desired state должно снять правило.
	a.applyFirewallPairs(nil)
	if got := len(r.DumpRules()); got != 0 {
		t.Fatalf("rules after removal = %d, want 0", got)
	}
}
