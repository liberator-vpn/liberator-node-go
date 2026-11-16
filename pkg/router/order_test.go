package router

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/liberator-vpn/liberator-node-go/internal/utils/dgmessage"
)

func testRouter(t *testing.T) (*Router, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r, err := New(ctx, "100.64.0.1", "100.64.0.0/10")
	if err != nil {
		cancel()
		t.Fatalf("New: %v", err)
	}
	return r, cancel
}

func flow(src, dst [4]byte, sport, dport uint16, proto string) dgmessage.HoleInfo {
	return dgmessage.HoleInfo{
		SrcIP:    binary.BigEndian.Uint32(src[:]),
		DstIP:    binary.BigEndian.Uint32(dst[:]),
		SrcPort:  sport,
		DstPort:  dport,
		Protocol: proto,
	}
}

func TestGetWorkerStableForSameFlow(t *testing.T) {
	r, cancel := testRouter(t)
	defer cancel()

	base := flow([4]byte{100, 64, 0, 4}, [4]byte{1, 1, 1, 1}, 40000, 443, "tcp")
	want := r.getWorker(base, fromTransport)
	if want == nil {
		t.Fatal("getWorker returned nil")
	}

	// Same 5-tuple, different packet contents / flags must not move the flow
	// to another worker: otherwise per-flow order is lost.
	for i := 0; i < 1000; i++ {
		hi := base
		hi.SrcPort = 40000
		if got := r.getWorker(hi, fromTransport); got != want {
			t.Fatalf("same flow moved to another worker at iteration %d", i)
		}
	}

	// Upload and download use disjoint pools, so the same 5-tuple must not
	// share a channel across directions.
	if got := r.getWorker(base, fromTun); got == want {
		t.Fatal("upload and download pools share a channel")
	}
}

func TestGetWorkerDistributesFlows(t *testing.T) {
	r, cancel := testRouter(t)
	defer cancel()

	seen := make(map[chan datagramMessageInfo]struct{})
	for i := 0; i < 256; i++ {
		hi := flow([4]byte{100, 64, 0, 4}, [4]byte{1, 1, 1, 1}, uint16(10000+i), 443, "tcp")
		seen[r.getWorker(hi, fromTransport)] = struct{}{}
	}
	if len(seen) < 2 {
		t.Fatalf("256 flows mapped to %d worker(s), expected distribution", len(seen))
	}
}

func TestEnqueuePreservesPerFlowOrder(t *testing.T) {
	r, cancel := testRouter(t)
	defer cancel()

	hi := flow([4]byte{100, 64, 0, 4}, [4]byte{8, 8, 8, 8}, 41000, 80, "tcp")
	worker := r.getWorker(hi, fromTransport)

	const n = 500
	for i := 0; i < n; i++ {
		msg := &dgmessage.DatagramMessage{
			Data:     []byte{byte(i >> 8), byte(i)},
			HoleInfo: hi,
		}
		r.enqueue(msg, fromTransport)
	}

	for i := 0; i < n; i++ {
		select {
		case info := <-worker:
			if info.From != fromTransport {
				t.Fatalf("packet %d: from=%d, want %d", i, info.From, fromTransport)
			}
			got := int(info.Msg.Data[0])<<8 | int(info.Msg.Data[1])
			if got != i {
				t.Fatalf("order broken: got packet %d, want %d", got, i)
			}
			info.Msg.Free()
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for packet %d", i)
		}
	}
}

func TestNewMessageCopyFromIPv4Options(t *testing.T) {
	r, cancel := testRouter(t)
	defer cancel()

	// IPv4 header with 4 bytes of options (IHL=6) + TCP header. Ports must be
	// read at ihl, otherwise the same flow hashes differently.
	pkt := make([]byte, 44)
	pkt[0] = 0x46 // IPv4, IHL=6
	pkt[9] = 6    // TCP
	copy(pkt[12:16], []byte{100, 64, 0, 4})
	copy(pkt[16:20], []byte{1, 1, 1, 1})
	binary.BigEndian.PutUint16(pkt[24:26], 42000)
	binary.BigEndian.PutUint16(pkt[26:28], 443)

	msg, err := r.NewMessageCopyFrom(pkt)
	if err != nil {
		t.Fatalf("NewMessageCopyFrom: %v", err)
	}
	defer msg.Free()

	if msg.HoleInfo.SrcPort != 42000 || msg.HoleInfo.DstPort != 443 {
		t.Fatalf("ports parsed at wrong offset: %+v", msg.HoleInfo)
	}
	if msg.HoleInfo.Protocol != "tcp" {
		t.Fatalf("protocol=%q, want tcp", msg.HoleInfo.Protocol)
	}

	// A normal 20-byte IP header with the same 5-tuple must hash identically.
	std := make([]byte, 40)
	std[0] = 0x45
	std[9] = 6
	copy(std[12:16], []byte{100, 64, 0, 4})
	copy(std[16:20], []byte{1, 1, 1, 1})
	binary.BigEndian.PutUint16(std[20:22], 42000)
	binary.BigEndian.PutUint16(std[22:24], 443)
	stdMsg, err := r.NewMessageCopyFrom(std)
	if err != nil {
		t.Fatalf("NewMessageCopyFrom std: %v", err)
	}
	defer stdMsg.Free()

	if got, want := r.getWorker(msg.HoleInfo, fromTransport), r.getWorker(stdMsg.HoleInfo, fromTransport); got != want {
		t.Fatal("IPv4 options changed the worker for the same flow")
	}
}
