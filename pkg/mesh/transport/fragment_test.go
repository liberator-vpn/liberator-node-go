package transport

import (
	"bytes"
	"testing"
)

func TestFragmentReassembleOutOfOrder(t *testing.T) {
	original := make([]byte, 3500)
	for i := range original {
		original[i] = byte(i)
	}

	frags := fragmentDatagram(42, original)
	if len(frags) < 3 {
		t.Fatalf("fragments = %d, want >= 3", len(frags))
	}

	r := newDatagramReassembler()
	// Перемешиваем порядок: QUIC DATAGRAM не гарантирует порядок.
	order := []int{2, 0, 3, 1}
	for _, i := range order {
		if i >= len(frags) {
			continue
		}
		got, ready, err := r.add(frags[i])
		if err != nil {
			t.Fatalf("add fragment %d: %v", i, err)
		}
		if ready {
			if !bytes.Equal(got, original) {
				t.Fatal("reassembled packet differs from original")
			}
			return
		}
	}
	t.Fatal("packet was not reassembled")
}

func TestFragmentMissingPartNeverCompletes(t *testing.T) {
	original := bytes.Repeat([]byte{0xAB}, 2500)
	frags := fragmentDatagram(7, original)

	r := newDatagramReassembler()
	for i := 0; i < len(frags)-1; i++ {
		got, ready, err := r.add(frags[i])
		if err != nil {
			t.Fatalf("add: %v", err)
		}
		if ready || got != nil {
			t.Fatal("incomplete packet must not be returned")
		}
	}
}

func TestFragmentDuplicateIsIgnored(t *testing.T) {
	original := bytes.Repeat([]byte{0xCD}, 2500)
	frags := fragmentDatagram(9, original)

	r := newDatagramReassembler()
	if _, _, err := r.add(frags[0]); err != nil {
		t.Fatal(err)
	}
	if _, ready, err := r.add(frags[0]); err != nil || ready {
		t.Fatalf("duplicate must be ignored, ready=%v err=%v", ready, err)
	}
}
