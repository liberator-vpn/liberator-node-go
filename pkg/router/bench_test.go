package router

import (
	"context"
	"testing"

	"github.com/liberator-vpn/liberator-node-go/internal/utils/netutils"
)

func BenchmarkLookupPolicyNoRules(b *testing.B) {
	r, err := New(context.Background(), "100.64.0.1", "100.64.0.0/10")
	if err != nil {
		b.Fatal(err)
	}
	src := netutils.IPStringToUint32("100.64.0.4")
	dst := netutils.IPStringToUint32("8.8.8.8")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.lookupPolicy(src, dst)
	}
}
