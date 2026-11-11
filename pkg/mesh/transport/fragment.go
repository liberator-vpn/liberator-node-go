package transport

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

// QUIC DATAGRAM не гарантирует доставку и имеет ограничение по размеру
// (обычно ~1200 байт на пути). Пакеты overlay могут быть до MTU (1376+),
// поэтому перед отправкой в меш режем их на фрагменты, а на приёме
// собираем обратно. Заголовок:
//
//	[0]      magic 0xF1
//	[1:3]    fragment index (uint16)
//	[3:5]    fragment count (uint16)
//	[5:9]    packet id (uint32)
//	[9:]     payload
//
// 0xF1 не может быть первым байтом IPv4-пакета (там 0x4x), поэтому
// неразделённые пакеты остаются на проводе без накладных расходов.
const (
	fragmentMagic      byte = 0xF1
	fragmentHeaderSize      = 9
	maxFragmentPayload      = 1000
	maxReassemblySets       = 128
	reassemblyTTL           = 30 * time.Second
	maxReassembledSize      = 65535
)

type fragmentSet struct {
	created time.Time
	count   uint16
	parts   map[uint16][]byte
	size    int
}

// datagramReassembler собирает фрагменты одного QUIC-соединения.
type datagramReassembler struct {
	mu   sync.Mutex
	sets map[uint32]*fragmentSet
}

func newDatagramReassembler() *datagramReassembler {
	return &datagramReassembler{sets: make(map[uint32]*fragmentSet)}
}

// fragmentDatagram режет data на фрагменты с общим id.
func fragmentDatagram(id uint32, data []byte) [][]byte {
	count := (len(data) + maxFragmentPayload - 1) / maxFragmentPayload
	if count == 0 {
		return nil
	}
	out := make([][]byte, 0, count)
	for i := 0; i < count; i++ {
		start := i * maxFragmentPayload
		end := start + maxFragmentPayload
		if end > len(data) {
			end = len(data)
		}
		buf := make([]byte, fragmentHeaderSize+end-start)
		buf[0] = fragmentMagic
		binary.BigEndian.PutUint16(buf[1:3], uint16(i))
		binary.BigEndian.PutUint16(buf[3:5], uint16(count))
		binary.BigEndian.PutUint32(buf[5:9], id)
		copy(buf[fragmentHeaderSize:], data[start:end])
		out = append(out, buf)
	}
	return out
}

// add принимает один фрагмент. ready=true означает, что пакет собран целиком.
func (r *datagramReassembler) add(data []byte) (packet []byte, ready bool, err error) {
	if len(data) < fragmentHeaderSize || data[0] != fragmentMagic {
		return nil, false, fmt.Errorf("not a fragment")
	}
	idx := binary.BigEndian.Uint16(data[1:3])
	count := binary.BigEndian.Uint16(data[3:5])
	id := binary.BigEndian.Uint32(data[5:9])
	if count == 0 || idx >= count {
		return nil, false, fmt.Errorf("invalid fragment %d/%d", idx, count)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	r.pruneLocked(now)

	set := r.sets[id]
	if set == nil {
		if len(r.sets) >= maxReassemblySets {
			return nil, false, fmt.Errorf("too many incomplete datagrams")
		}
		set = &fragmentSet{created: now, count: count, parts: make(map[uint16][]byte, count)}
		r.sets[id] = set
	}
	if set.count != count {
		delete(r.sets, id)
		return nil, false, fmt.Errorf("fragment count mismatch for datagram %d", id)
	}
	if _, exists := set.parts[idx]; exists {
		return nil, false, nil // дубликат: QUIC может доставить повторно
	}

	payload := data[fragmentHeaderSize:]
	if set.size+len(payload) > maxReassembledSize {
		delete(r.sets, id)
		return nil, false, fmt.Errorf("reassembled datagram too large")
	}
	set.parts[idx] = payload
	set.size += len(payload)

	if len(set.parts) != int(count) {
		return nil, false, nil
	}

	packet = make([]byte, 0, set.size)
	for i := uint16(0); i < count; i++ {
		part, ok := set.parts[i]
		if !ok {
			return nil, false, nil
		}
		packet = append(packet, part...)
	}
	delete(r.sets, id)
	return packet, true, nil
}

func (r *datagramReassembler) pruneLocked(now time.Time) {
	for id, set := range r.sets {
		if now.Sub(set.created) > reassemblyTTL {
			delete(r.sets, id)
		}
	}
}
