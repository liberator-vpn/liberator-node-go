package awg

import (
	"context"
	"testing"
	"time"
)

// Device.Close() ждет RoutineTUNEventReader, который висит в range по Events().
// Канал обязан быть один на устройство и закрываться в Close, иначе шатдаун виснет.
func TestChannelTunEventsClose(t *testing.T) {
	tn := NewChannelTun(context.Background(), nil, nil, 1376)

	if tn.Events() != tn.Events() {
		t.Fatal("Events must return the same channel, a fresh one is never closed")
	}

	done := make(chan struct{})
	go func() {
		for range tn.Events() {
		}
		close(done)
	}()

	_ = tn.Close()
	_ = tn.Close() // повторный вызов не должен паниковать

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("event reader did not stop after Close")
	}
}
