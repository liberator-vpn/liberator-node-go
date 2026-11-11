package firewall

import (
	"testing"
	"time"

	"github.com/liberator-vpn/liberator-node-go/internal/utils/dgmessage"
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

// Пары (recipient, sender) раньше усекались до 48 бит, поэтому получатели,
// отличающиеся только старшими 16 битами IP, коллизировали. Оба правила
// должны существовать и разрешать свой поток.
func TestRuleIDsDoNotCollideAcrossRecipients(t *testing.T) {
	fw := New()
	// Имитируем pairRuleID = recipient<<32 | sender.
	const sender = uint32(0x0A000002) // 10.0.0.2
	recA := uint32(0x0A010003)        // 10.1.0.3
	recB := uint32(0x0A020003)        // 10.2.0.3
	anyPort := uint16(65535)

	for i, rec := range []uint32{recA, recB} {
		idx := PortRuleIndex{NodeID: "node", RuleID: uint64(rec)<<32 | uint64(sender)}
		if !fw.AddRule(idx, PortRule{
			Address: rec, TargetAddress: ptr(sender), Protocol: "both",
			PortRangeStart: 0, PortRangeEnd: &anyPort,
		}) {
			t.Fatalf("rule %d for recipient %d rejected (collision)", i, rec)
		}
	}

	for _, rec := range []uint32{recA, recB} {
		hi := dgmessage.HoleInfo{SrcIP: sender, DstIP: rec, SrcPort: 5000, DstPort: 443, Protocol: "tcp"}
		if !fw.RuleCheck(hi) {
			t.Fatalf("flow to recipient %d must be allowed", rec)
		}
	}
}

// Пара из API не несёт порт: правило должно разрешать любой dstPort, а не
// только 0 (раньше nil PortRangeEnd означал «ровно PortRangeStart»).
func TestFullPortRangeAllowsAnyDestinationPort(t *testing.T) {
	fw := New()
	anyPort := uint16(65535)
	idx := PortRuleIndex{NodeID: "node", RuleID: 1}
	if !fw.AddRule(idx, PortRule{
		Address: 200, TargetAddress: ptr(100), Protocol: "both",
		PortRangeStart: 0, PortRangeEnd: &anyPort,
	}) {
		t.Fatal("failed to add rule")
	}
	for _, port := range []uint16{0, 443, 65535} {
		hi := dgmessage.HoleInfo{SrcIP: 100, DstIP: 200, SrcPort: 1234, DstPort: port, Protocol: "tcp"}
		if !fw.RuleCheck(hi) {
			t.Fatalf("port %d must be allowed", port)
		}
	}
}

func ptr(v uint32) *uint32 { return &v }

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
