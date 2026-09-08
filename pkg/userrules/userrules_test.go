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
		if got := r.Lookup(c.src, c.dst); got != c.want {
			t.Fatalf("Lookup(%v,%v) = %q, want %q", c.src, c.dst, got, c.want)
		}
	}

	r.Clear()
	if got := r.Lookup(src, netutils.IPStringToUint32("10.1.2.3")); got != "" {
		t.Fatalf("expected empty after Clear, got %q", got)
	}
}
