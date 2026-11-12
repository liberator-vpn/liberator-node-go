package userrules

import (
	"testing"

	"github.com/liberator-vpn/liberator-node-go/internal/utils/netutils"
)

func TestUserRulesLongestPrefix(t *testing.T) {
	r := New()
	r.Set(netutils.IPStringToUint32("10.1.0.2"), "10.0.0.0/8", "exit-a")
	r.Set(netutils.IPStringToUint32("10.1.0.2"), "10.1.0.0/16", "exit-b")

	src := netutils.IPStringToUint32("10.1.0.2")
	other := netutils.IPStringToUint32("10.1.0.3")

	cases := []struct {
		src, dst uint32
		want     string
	}{
		{src, netutils.IPStringToUint32("10.1.2.3"), "exit-b"},
		{src, netutils.IPStringToUint32("10.9.8.7"), "exit-a"},
		{src, netutils.IPStringToUint32("8.8.8.8"), ""},
		{other, netutils.IPStringToUint32("10.1.2.3"), ""},
	}
	for _, c := range cases {
		action, got := r.Lookup(c.src, c.dst)
		wantAction := ActionDirect
		if c.want != "" {
			wantAction = ActionExit
		}
		if got != c.want || action != wantAction {
			t.Fatalf("Lookup(%v,%v) = (%q,%q), want (%q,%q)", c.src, c.dst, action, got, wantAction, c.want)
		}
	}

	r.Clear()
	if _, got := r.Lookup(src, netutils.IPStringToUint32("10.1.2.3")); got != "" {
		t.Fatalf("expected empty after Clear, got %q", got)
	}
}

func TestUserRulesReplaceAllIsAtomicAndValidates(t *testing.T) {
	r := New()
	src := netutils.IPStringToUint32("10.1.0.2")
	r.Set(src, "10.0.0.0/8", "old")

	invalid := r.ReplaceAll([]Entry{
		{ClientIP: src, PrefixCIDR: "10.1.0.0/16", Exit: "exit-a"},
		{ClientIP: src, PrefixCIDR: "not-a-cidr", Exit: "bad"},
		{ClientIP: src, PrefixCIDR: "2001:db8::/32", Exit: "v6"},
	})
	if invalid != 2 {
		t.Fatalf("invalid = %d, want 2", invalid)
	}
	// Старое правило должно исчезнуть полностью (замена, не append).
	if _, got := r.Lookup(src, netutils.IPStringToUint32("10.9.8.7")); got != "" {
		t.Fatalf("old rule survived ReplaceAll: %q", got)
	}
	if _, got := r.Lookup(src, netutils.IPStringToUint32("10.1.2.3")); got != "exit-a" {
		t.Fatalf("new rule not applied: %q", got)
	}
}

func TestDenyAndDirectActions(t *testing.T) {
	r := New()
	src := netutils.IPStringToUint32("100.64.0.2")
	r.ReplaceAll([]Entry{
		{ClientIP: src, PrefixCIDR: "198.51.100.0/24", Action: ActionDeny},
		{ClientIP: src, PrefixCIDR: "203.0.113.0/24", Action: ActionDirect},
	})
	action, exit := r.Lookup(src, netutils.IPStringToUint32("198.51.100.7"))
	if action != ActionDeny || exit != "" {
		t.Fatalf("deny lookup = (%q,%q)", action, exit)
	}
	action, exit = r.Lookup(src, netutils.IPStringToUint32("203.0.113.7"))
	if action != ActionDirect || exit != "" {
		t.Fatalf("direct lookup = (%q,%q)", action, exit)
	}
}

func TestUserTierOverridesMoreSpecificGroup(t *testing.T) {
	r := New()
	src := netutils.IPStringToUint32("100.64.0.2")
	r.ReplaceAll([]Entry{
		{ClientIP: src, PrefixCIDR: "10.0.0.0/16", Action: ActionExit, Exit: "user-exit", Tier: 0},
		{ClientIP: src, PrefixCIDR: "10.0.1.0/24", Action: ActionDeny, Tier: 1, GroupPriority: 1},
	})
	action, exit := r.Lookup(src, netutils.IPStringToUint32("10.0.1.7"))
	if action != ActionExit || exit != "user-exit" {
		t.Fatalf("user tier must win: (%q,%q)", action, exit)
	}
}
