package router

import (
	"net"
	"testing"
	"time"

	"github.com/liberator-vpn/liberator-node-go/internal/utils/netutils"
	"github.com/liberator-vpn/liberator-node-go/pkg/dnsproxy"
	"github.com/liberator-vpn/liberator-node-go/pkg/domainrules"
	"github.com/liberator-vpn/liberator-node-go/pkg/userrules"
)

// domainPolicy ставит domain-правило и DNS-кэш так, чтобы lookupPolicy
// находил совпадение по dst.
func domainPolicy(t *testing.T, r *Router, src, dst uint32, action, exit string) {
	t.Helper()
	cache := dnsproxy.NewCache(dnsproxy.CacheConfig{TTL: time.Minute, MaxEntries: 10})
	cache.Put("example.com", []net.IP{net.ParseIP(netutils.Uint32ToIPString(dst))})
	cache.PutClient(src, "example.com", []net.IP{net.ParseIP(netutils.Uint32ToIPString(dst))})
	r.SetDomainPolicy(domainrules.New(), cache)
	// Первый цикл синка фиксирует пустой набор IP-правил; иначе первый же
	// вызов ReplaceEgressRules в тесте сбросит только что поставленный пин.
	r.ReplaceEgressRules(nil)
	r.ReplaceDomainRules([]domainrules.Entry{{
		ClientIP: src, Domain: "example.com", Action: action, Exit: exit,
	}})
	r.lookupPolicy(src, dst)
}

// Регресс: после выключения domain-правила кэш решений не должен продолжать
// слать трафик на старую exit-ноду.
func TestDomainPinInvalidatedWhenRuleRemoved(t *testing.T) {
	r := newPolicyRouter(t)
	src := netutils.IPStringToUint32("100.64.0.5")
	dst := netutils.IPStringToUint32("10.1.2.3")
	domainPolicy(t, r, src, dst, userrules.ActionExit, "de-1")

	action, exit := r.lookupPolicy(src, dst)
	if action != userrules.ActionExit || exit != "de-1" {
		t.Fatalf("before: action/exit = %q/%q, want exit/de-1", action, exit)
	}

	// Правило деактивировано: API присылает пустой набор.
	r.ReplaceDomainRules(nil)

	action, exit = r.lookupPolicy(src, dst)
	if action != userrules.ActionDirect || exit != "" {
		t.Fatalf("after removal: action/exit = %q/%q, want direct/\"\"", action, exit)
	}
}

// Изменение IP-правил тоже должно сбрасывать доменный кэш.
func TestDomainPinInvalidatedWhenEgressRulesChange(t *testing.T) {
	r := newPolicyRouter(t)
	src := netutils.IPStringToUint32("100.64.0.5")
	dst := netutils.IPStringToUint32("10.1.2.3")
	domainPolicy(t, r, src, dst, userrules.ActionExit, "de-1")

	if _, _, ok := r.getPin(src, dst); !ok {
		t.Fatal("pin was not set")
	}

	r.ReplaceEgressRules([]userrules.Entry{{
		ClientIP: src, PrefixCIDR: "0.0.0.0/0", Action: userrules.ActionDirect,
	}})

	if _, _, ok := r.getPin(src, dst); ok {
		t.Fatal("pin survived egress rule change")
	}
}

// Реконсиляция с тем же набором правил (раз в 5 секунд) не должна убивать
// stickiness уже установленных flow.
func TestPinSurvivesIdenticalReconcile(t *testing.T) {
	r := newPolicyRouter(t)
	src := netutils.IPStringToUint32("100.64.0.5")
	dst := netutils.IPStringToUint32("10.1.2.3")
	domainPolicy(t, r, src, dst, userrules.ActionExit, "de-1")

	if _, _, ok := r.getPin(src, dst); !ok {
		t.Fatal("pin was not set")
	}

	// Тот же набор правил, другой порядок записей.
	r.ReplaceDomainRules([]domainrules.Entry{{
		ClientIP: src, Domain: "example.com", Action: userrules.ActionExit, Exit: "de-1",
	}})
	r.ReplaceEgressRules(nil)

	if _, exit, ok := r.getPin(src, dst); !ok || exit != "de-1" {
		t.Fatalf("pin lost on identical reconcile: ok=%v exit=%q", ok, exit)
	}
}

// Пин, поставленный до смены поколения, не должен применяться.
func TestStaleGenerationPinRejected(t *testing.T) {
	r := newPolicyRouter(t)
	src := netutils.IPStringToUint32("100.64.0.5")
	dst := netutils.IPStringToUint32("10.1.2.3")
	domainPolicy(t, r, src, dst, userrules.ActionExit, "de-1")

	r.setPin(src, dst, userrules.ActionExit, "de-1")
	if _, _, ok := r.getPin(src, dst); !ok {
		t.Fatal("fresh pin must be valid")
	}

	// Эмулируем пин, оставшийся от предыдущего поколения правил.
	key := uint64(src)<<32 | uint64(dst)
	r.pinsMu.Lock()
	p := r.pins[key]
	p.gen = r.rulesGen - 1
	r.pins[key] = p
	r.pinsMu.Unlock()

	if _, _, ok := r.getPin(src, dst); ok {
		t.Fatal("pin from previous rule generation must be rejected")
	}
}
