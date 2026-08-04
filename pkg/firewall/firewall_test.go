package firewall

import (
	"testing"
	"time"

	"github.com/TexHik620953/liberator-node-go/internal/utils/dgmessage"
)

func flow() dgmessage.HoleInfo {
	return dgmessage.HoleInfo{SrcIP: 100, DstIP: 200, SrcPort: 5000, DstPort: 443, Protocol: "tcp"}
}

// Удаление правила должно рвать уже идущий поток: дырка продлевается каждым пакетом,
// поэтому без инвалидации трафик шел бы вечно.
func TestRemoveRuleClosesAuthorizedFlow(t *testing.T) {
	fw := New()
	idx := PortRuleIndex{NodeID: "node", RuleID: 1}

	if !fw.AddRule(idx, PortRule{Address: 200, Protocol: "tcp", PortRangeStart: 443}) {
		t.Fatal("failed to add rule")
	}
	if !fw.RuleCheck(flow()) {
		t.Fatal("rule must allow the flow")
	}
	fw.Holepunch(flow(), time.Minute) // роутер делает это на каждом пакете потока

	if !fw.RemoveRule(idx) {
		t.Fatal("failed to remove rule")
	}
	if fw.RuleCheck(flow()) {
		t.Fatal("flow must stop once its rule is gone")
	}
}

func TestRemoveRuleKeepsUnrelatedFlow(t *testing.T) {
	fw := New()
	keep := PortRuleIndex{NodeID: "node", RuleID: 1}
	drop := PortRuleIndex{NodeID: "node", RuleID: 2}

	fw.AddRule(keep, PortRule{Address: 200, Protocol: "tcp", PortRangeStart: 443})
	fw.AddRule(drop, PortRule{Address: 201, Protocol: "tcp", PortRangeStart: 80})
	fw.Holepunch(flow(), time.Minute)

	if !fw.RemoveRule(drop) {
		t.Fatal("failed to remove rule")
	}
	if !fw.RuleCheck(flow()) {
		t.Fatal("unrelated removal must not close the flow")
	}
}
