package router

import (
	"net/netip"
	"testing"

	"github.com/liberator-vpn/liberator-node-go/internal/utils/netutils"
	"github.com/liberator-vpn/liberator-node-go/pkg/userrules"
)

func TestPrefixTrieLongestMatch(t *testing.T) {
	trie := newPrefixTrie()
	trie.insert(mustPrefix(t, "0.0.0.0/0"), groupRule{action: "exit", exit: "any"})
	trie.insert(mustPrefix(t, "10.0.0.0/8"), groupRule{action: "direct"})
	trie.insert(mustPrefix(t, "10.1.0.0/16"), groupRule{action: "deny"})

	cases := []struct {
		dst    string
		action string
		bits   int
	}{
		{"10.1.2.3", "deny", 16},
		{"10.9.8.7", "direct", 8},
		{"8.8.8.8", "exit", 0},
	}
	for _, c := range cases {
		rule, bits, ok := trie.lookup(netutils.IPStringToUint32(c.dst))
		if !ok || rule.action != c.action || bits != c.bits {
			t.Fatalf("%s: got (%q,%d,%v), want (%q,%d,true)", c.dst, rule.action, bits, ok, c.action, c.bits)
		}
	}
}

func TestGroupRulesBestAcrossGroups(t *testing.T) {
	r := newPolicyRouter(t)
	src := netutils.IPStringToUint32("100.64.0.5")
	r.ReplaceGroupRules([]GroupInput{
		{ID: "g1", Priority: 10, Rules: []GroupRuleInput{
			{Prefix: "0.0.0.0/0", Action: userrules.ActionExit, Exit: "exit-g1"},
			{Prefix: "10.1.0.0/16", Action: userrules.ActionDeny},
		}},
		{ID: "g2", Priority: 1, Rules: []GroupRuleInput{
			{Prefix: "10.0.0.0/8", Action: userrules.ActionDirect},
		}},
	})
	r.ReplaceClientGroups([]ClientGroupsInput{{ClientIP: src, GroupIDs: []string{"g1", "g2"}}})

	gl := r.lookupGroups(src, netutils.IPStringToUint32("10.1.2.3"), nil, nil)
	if !gl.ipOK || gl.ipRule.action != userrules.ActionDeny || gl.ipBits != 16 {
		t.Fatalf("more specific rule must win: %+v", gl)
	}

	gl = r.lookupGroups(src, netutils.IPStringToUint32("10.9.8.7"), nil, nil)
	if !gl.ipOK || gl.ipRule.action != userrules.ActionDirect || gl.ipBits != 8 {
		t.Fatalf("/8 must beat /0: %+v", gl)
	}

	gl = r.lookupGroups(src, netutils.IPStringToUint32("8.8.8.8"), nil, nil)
	if !gl.ipOK || gl.ipRule.action != userrules.ActionExit || gl.ipRule.exit != "exit-g1" {
		t.Fatalf("default group rule must apply: %+v", gl)
	}
}

func TestUserRuleBeatsGroupRule(t *testing.T) {
	r := newPolicyRouter(t)
	src := netutils.IPStringToUint32("100.64.0.5")
	dst := netutils.IPStringToUint32("10.1.2.3")

	r.ReplaceEgressRules([]userrules.Entry{{
		ClientIP: src, PrefixCIDR: "10.0.0.0/8", Action: userrules.ActionDirect,
	}})
	r.ReplaceGroupRules([]GroupInput{{
		ID: "g1", Priority: 10,
		Rules: []GroupRuleInput{{Prefix: "10.1.0.0/16", Action: userrules.ActionDeny}},
	}})
	r.ReplaceClientGroups([]ClientGroupsInput{{ClientIP: src, GroupIDs: []string{"g1"}}})

	action, _ := r.lookupPolicy(src, dst)
	if action != userrules.ActionDirect {
		t.Fatalf("user tier must win over group tier: %q", action)
	}
}

func TestGroupDenyWithoutUserRule(t *testing.T) {
	r := newPolicyRouter(t)
	src := netutils.IPStringToUint32("100.64.0.5")
	dst := netutils.IPStringToUint32("10.1.2.3")

	r.ReplaceGroupRules([]GroupInput{{
		ID: "g1", Priority: 10,
		Rules: []GroupRuleInput{{Prefix: "10.1.0.0/16", Action: userrules.ActionDeny}},
	}})
	r.ReplaceClientGroups([]ClientGroupsInput{{ClientIP: src, GroupIDs: []string{"g1"}}})

	action, _ := r.lookupPolicy(src, dst)
	if action != userrules.ActionDeny {
		t.Fatalf("group deny must apply: %q", action)
	}
}

func TestGroupPinInvalidatedOnRuleChange(t *testing.T) {
	r := newPolicyRouter(t)
	src := netutils.IPStringToUint32("100.64.0.5")
	dst := netutils.IPStringToUint32("10.1.2.3")

	r.ReplaceGroupRules([]GroupInput{{
		ID: "g1", Priority: 10,
		Rules: []GroupRuleInput{{Prefix: "10.1.0.0/16", Action: userrules.ActionExit, Exit: "de-1"}},
	}})
	r.ReplaceClientGroups([]ClientGroupsInput{{ClientIP: src, GroupIDs: []string{"g1"}}})

	if action, exit := r.lookupPolicy(src, dst); action != userrules.ActionExit || exit != "de-1" {
		t.Fatalf("group exit must apply: %q/%q", action, exit)
	}

	// Групповое правило убрали — пин не должен пережить изменение.
	r.ReplaceGroupRules(nil)
	if action, _ := r.lookupPolicy(src, dst); action != userrules.ActionDirect {
		t.Fatalf("stale group decision survived: %q", action)
	}
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return p
}

func BenchmarkGroupTrieLookup(b *testing.B) {
	trie := newPrefixTrie()
	trie.insert(netip.MustParsePrefix("0.0.0.0/0"), groupRule{action: userrules.ActionExit})
	for i := 0; i < 40000; i++ {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i / 256), byte(i % 256), 0}), 24)
		trie.insert(p, groupRule{action: userrules.ActionDirect})
	}
	b.ResetTimer()
	sink := 0
	for i := 0; i < b.N; i++ {
		rule, bits, ok := trie.lookup(uint32(i))
		if ok {
			sink += bits + len(rule.action)
		}
	}
	_ = sink
}
