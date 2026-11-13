package router

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/liberator-vpn/liberator-node-go/internal/utils/dgmessage"
	"github.com/liberator-vpn/liberator-node-go/internal/utils/netutils"
	"github.com/liberator-vpn/liberator-node-go/pkg/dnsproxy"
	"github.com/liberator-vpn/liberator-node-go/pkg/domainrules"
	"github.com/liberator-vpn/liberator-node-go/pkg/userrules"
)

func newPolicyRouter(t *testing.T) *Router {
	t.Helper()
	r, err := New(context.Background(), "100.64.0.1", "100.64.0.0/10")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestPolicyIPDenyBeatsDomain(t *testing.T) {
	r := newPolicyRouter(t)
	src := netutils.IPStringToUint32("100.64.0.5")
	dst := netutils.IPStringToUint32("10.1.2.3")
	r.userRules.ReplaceAll([]userrules.Entry{{
		ClientIP: src, PrefixCIDR: "10.0.0.0/8", Action: userrules.ActionDeny,
	}})
	rules := domainrules.New()
	rules.ReplaceAll([]domainrules.Entry{{
		ClientIP: src, Domain: "example.com", Action: userrules.ActionDirect,
	}})
	cache := dnsproxy.NewCache(dnsproxy.CacheConfig{TTL: time.Minute, MaxEntries: 10})
	cache.Put("example.com", []net.IP{net.ParseIP("10.1.2.3")})
	cache.PutClient(src, "example.com", []net.IP{net.ParseIP("10.1.2.3")})
	r.SetDomainPolicy(rules, cache)

	action, _ := r.lookupPolicy(src, dst)
	if action != userrules.ActionDeny {
		t.Fatalf("action = %q, want deny", action)
	}
}

func TestPolicyDomainExitOverridesIPDirect(t *testing.T) {
	r := newPolicyRouter(t)
	src := netutils.IPStringToUint32("100.64.0.5")
	dst := netutils.IPStringToUint32("10.1.2.3")
	r.userRules.ReplaceAll([]userrules.Entry{{
		ClientIP: src, PrefixCIDR: "10.0.0.0/8", Action: userrules.ActionDirect,
	}})
	rules := domainrules.New()
	rules.ReplaceAll([]domainrules.Entry{{
		ClientIP: src, Domain: "example.com", Action: userrules.ActionExit, Exit: "de-1",
	}})
	cache := dnsproxy.NewCache(dnsproxy.CacheConfig{TTL: time.Minute, MaxEntries: 10})
	cache.Put("example.com", []net.IP{net.ParseIP("10.1.2.3")})
	cache.PutClient(src, "example.com", []net.IP{net.ParseIP("10.1.2.3")})
	r.SetDomainPolicy(rules, cache)

	action, exit := r.lookupPolicy(src, dst)
	if action != userrules.ActionExit || exit != "de-1" {
		t.Fatalf("action/exit = %q/%q, want exit/de-1", action, exit)
	}
}

func TestPolicySharedIPDenyFromGlobalDomain(t *testing.T) {
	r := newPolicyRouter(t)
	src := netutils.IPStringToUint32("100.64.0.5")
	dst := netutils.IPStringToUint32("10.1.2.3")
	rules := domainrules.New()
	rules.ReplaceAll([]domainrules.Entry{
		{ClientIP: src, Domain: "blocked.com", Action: userrules.ActionDeny},
		{ClientIP: src, Domain: "allowed.com", Action: userrules.ActionDirect},
	})
	cache := dnsproxy.NewCache(dnsproxy.CacheConfig{TTL: time.Minute, MaxEntries: 10})
	cache.Put("blocked.com", []net.IP{net.ParseIP("10.1.2.3")})
	cache.Put("allowed.com", []net.IP{net.ParseIP("10.1.2.3")})
	cache.PutClient(src, "allowed.com", []net.IP{net.ParseIP("10.1.2.3")})
	r.SetDomainPolicy(rules, cache)

	action, _ := r.lookupPolicy(src, dst)
	if action != userrules.ActionDeny {
		t.Fatalf("action = %q, want deny", action)
	}
}

func TestGatewayAllowsOnlyDNSAndICMP(t *testing.T) {
	cases := []struct {
		hi   dgmessage.HoleInfo
		want bool
	}{
		{dgmessage.HoleInfo{Protocol: "udp", DstPort: 53}, true},
		{dgmessage.HoleInfo{Protocol: "tcp", DstPort: 53}, true},
		{dgmessage.HoleInfo{Protocol: "icmp"}, true},
		{dgmessage.HoleInfo{Protocol: "tcp", DstPort: 8080}, false},
		{dgmessage.HoleInfo{Protocol: "tcp", DstPort: 22}, false},
		{dgmessage.HoleInfo{Protocol: "udp", DstPort: 443}, false},
	}
	for _, c := range cases {
		if got := isAllowedGatewayPacket(c.hi); got != c.want {
			t.Fatalf("isAllowedGatewayPacket(%+v) = %v, want %v", c.hi, got, c.want)
		}
	}
}

func TestForbiddenEgressHardening(t *testing.T) {
	for _, ip := range []string{"10.0.0.1", "192.168.1.1", "100.64.0.1", "100.100.100.200", "192.0.2.1", "198.51.100.1", "203.0.113.1"} {
		if !isForbiddenEgress(netutils.IPStringToUint32(ip)) {
			t.Fatalf("%s must be forbidden", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "203.0.114.1"} {
		if isForbiddenEgress(netutils.IPStringToUint32(ip)) {
			t.Fatalf("%s must be allowed", ip)
		}
	}
}
