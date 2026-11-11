package routingtable

import (
	"context"
	"testing"

	"github.com/liberator-vpn/liberator-node-go/internal/utils/dgmessage"
)

type fakeRoute struct {
	sent int
}

func (f *fakeRoute) GetNodeID() string        { return "node" }
func (f *fakeRoute) GetVirtualIP() uint32     { return 1 }
func (f *fakeRoute) Context() context.Context { return context.Background() }
func (f *fakeRoute) SendDatagram([]byte) error {
	f.sent++
	return nil
}

// Нулевой traffic-limit — это способ ноды выполнить over_limit: шейпер
// обязан дропать пакеты, а не отправлять их.
func TestShapedRouteZeroTrafficLimitDrops(t *testing.T) {
	underlying := &fakeRoute{}
	zero := uint64(0)
	sr := NewShapedRoute(underlying, nil, &zero)

	msg := &dgmessage.DatagramMessage{Data: make([]byte, 100)}
	if err := sr.PushLimited(msg); err != nil {
		t.Fatalf("PushLimited: %v", err)
	}
	if underlying.sent != 0 {
		t.Fatalf("sent %d packets, want 0", underlying.sent)
	}
	if sr.IsAllowed(100) {
		t.Fatal("IsAllowed must be false when traffic limit is exhausted")
	}
}
