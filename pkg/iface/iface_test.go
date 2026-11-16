package iface

import "testing"

// writeProjection must cap capacity at one flat-buffer segment. wireguard/tun
// handleGRO uses cap() to decide how much it may coalesce; an unbounded cap
// lets it merge the whole TCP batch, overflow the 16-bit IP length and hand a
// corrupt GSO packet to the kernel.
func TestWriteProjectionCapacityIsBounded(t *testing.T) {
	const maxPacketLen = 65535 + tun_iface_offset
	const batchSize = 4

	flat := make([]byte, batchSize*maxPacketLen)
	for i := 0; i < batchSize; i++ {
		start := i * maxPacketLen
		end := start + tun_iface_offset + 1376
		p := writeProjection(flat, start, end, maxPacketLen)

		if len(p) != tun_iface_offset+1376 {
			t.Fatalf("projection %d: len=%d, want %d", i, len(p), tun_iface_offset+1376)
		}
		if cap(p) != maxPacketLen {
			t.Fatalf("projection %d: cap=%d, want %d", i, cap(p), maxPacketLen)
		}
		if cap(p) >= len(flat) && i == 0 {
			t.Fatalf("projection 0: cap=%d is not bounded to one segment", cap(p))
		}
	}
}
