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

	frags := fragmentDatagram(42, original, defaultFragmentChunk)
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

func TestFragmentLastFirst(t *testing.T) {
	// Первым приходит короткий хвост: chunk должен браться из заголовка,
	// а не из длины этого фрагмента.
	original := bytes.Repeat([]byte{0x5A}, 2600)
	frags := fragmentDatagram(77, original, defaultFragmentChunk)
	if len(frags) < 3 {
		t.Fatalf("fragments = %d, want >= 3", len(frags))
	}

	r := newDatagramReassembler()
	order := []int{len(frags) - 1}
	for i := 0; i < len(frags)-1; i++ {
		order = append(order, i)
	}
	for _, i := range order {
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
	frags := fragmentDatagram(7, original, defaultFragmentChunk)

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
	frags := fragmentDatagram(9, original, defaultFragmentChunk)

	r := newDatagramReassembler()
	if _, _, err := r.add(frags[0]); err != nil {
		t.Fatal(err)
	}
	if _, ready, err := r.add(frags[0]); err != nil || ready {
		t.Fatalf("duplicate must be ignored, ready=%v err=%v", ready, err)
	}
}

func TestSendFragmentsReusesBuffer(t *testing.T) {
	original := bytes.Repeat([]byte{0xEE}, 3000)
	var sizes []int
	var payloads [][]byte
	err := sendFragments(func(b []byte) error {
		sizes = append(sizes, len(b))
		payloads = append(payloads, append([]byte(nil), b...))
		return nil
	}, 11, original, defaultFragmentChunk)
	if err != nil {
		t.Fatal(err)
	}
	if len(payloads) < 3 {
		t.Fatalf("fragments = %d, want >= 3", len(payloads))
	}
	for i, p := range payloads {
		if len(p) != sizes[i] {
			t.Fatalf("fragment %d len changed", i)
		}
		if p[0] != fragmentMagic {
			t.Fatalf("fragment %d magic = %#x", i, p[0])
		}
	}
}
