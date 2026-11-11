package xray

import (
	"encoding/binary"
	"testing"
)

func buildTCPPacket(src, dst uint32) []byte {
	payload := []byte("hello")
	tcp := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(tcp[0:2], 12345)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	tcp[12] = 5 << 4 // data offset
	copy(tcp[20:], payload)

	ip := make([]byte, 20+len(tcp))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[8] = 64
	ip[9] = 6
	binary.BigEndian.PutUint32(ip[12:16], src)
	binary.BigEndian.PutUint32(ip[16:20], dst)

	// корректный TCP checksum (с pseudo-header)
	binary.BigEndian.PutUint16(tcp[16:18], 0)
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], ip[12:16])
	copy(pseudo[4:8], ip[16:20])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))
	full := append(append([]byte{}, pseudo...), tcp...)
	cs := checksum16(full, 0)
	binary.BigEndian.PutUint16(tcp[16:18], cs)
	copy(ip[20:], tcp)

	ip[10], ip[11] = 0, 0
	binary.BigEndian.PutUint16(ip[10:12], checksum16(ip[:20], 0))
	return ip
}

func fullTCPChecksum(packet []byte) uint16 {
	ihl := int(packet[0]&0x0f) * 4
	tcp := append([]byte{}, packet[ihl:]...)
	binary.BigEndian.PutUint16(tcp[16:18], 0)
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], packet[12:16])
	copy(pseudo[4:8], packet[16:20])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))
	return checksum16(append(pseudo, tcp...), 0)
}

func TestRewriteSourceUpdatesChecksums(t *testing.T) {
	pkt := buildTCPPacket(0xC6120002, 0x08080808) // 198.18.0.2 -> 8.8.8.8
	if checksum16(pkt[:20], 0) != 0 {
		t.Fatal("initial IP checksum is invalid")
	}
	newSrc := uint32(0x6440000A) // 100.64.0.10
	if !rewriteIPv4Source(pkt, newSrc) {
		t.Fatal("rewrite failed")
	}
	if got := binary.BigEndian.Uint32(pkt[12:16]); got != newSrc {
		t.Fatalf("source = %x", got)
	}
	if checksum16(pkt[:20], 0) != 0 {
		t.Fatal("IP checksum is invalid after rewrite")
	}
	ihl := int(pkt[0]&0x0f) * 4
	if got, want := binary.BigEndian.Uint16(pkt[ihl+16:ihl+18]), fullTCPChecksum(pkt); got != want {
		t.Fatalf("TCP checksum = %04x, want %04x", got, want)
	}
}

func TestRewriteDestinationUpdatesChecksums(t *testing.T) {
	pkt := buildTCPPacket(0x08080808, 0xC6120002)
	newDst := uint32(0xC6120002)
	if !rewriteIPv4Destination(pkt, newDst) {
		t.Fatal("rewrite failed")
	}
	if got := binary.BigEndian.Uint32(pkt[16:20]); got != newDst {
		t.Fatalf("destination = %x", got)
	}
	if checksum16(pkt[:20], 0) != 0 {
		t.Fatal("IP checksum is invalid after rewrite")
	}
	ihl := int(pkt[0]&0x0f) * 4
	if got, want := binary.BigEndian.Uint16(pkt[ihl+16:ihl+18]), fullTCPChecksum(pkt); got != want {
		t.Fatalf("TCP checksum = %04x, want %04x", got, want)
	}
}

func TestRewriteSkipsUDPZeroChecksum(t *testing.T) {
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[9] = 17
	binary.BigEndian.PutUint32(pkt[12:16], 0x01020304)
	binary.BigEndian.PutUint32(pkt[16:20], 0x08080808)
	// UDP checksum = 0 (не считать)
	if !rewriteIPv4Source(pkt, 0x0A000001) {
		t.Fatal("rewrite failed")
	}
	if got := binary.BigEndian.Uint16(pkt[26:28]); got != 0 {
		t.Fatalf("UDP checksum = %04x, want 0", got)
	}
}
