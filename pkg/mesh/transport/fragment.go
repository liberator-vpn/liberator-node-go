package transport

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

// QUIC DATAGRAM не гарантирует доставку и имеет ограничение по размеру
// (обычно ~1200-1400 байт на пути). Пакеты overlay могут быть до MTU (1420),
// поэтому если датаграмма не влезает целиком, режем её на фрагменты, а на
// приёме собираем обратно. Заголовок:
//
//	[0]      magic 0xF2
//	[1:3]    fragment index (uint16)
//	[3:5]    fragment count (uint16)
//	[5:9]    packet id (uint32)
//	[9:11]   chunk size (uint16, payload bytes in a full fragment)
//	[11:]    payload
//
// Chunk size в заголовке нужен, чтобы reassembler мог выделить один буфер и
// разложить фрагменты по смещениям независимо от порядка прихода. Раньше
// размер брался из первого пришедшего фрагмента, и если первым приходил
// короткий хвост, полные фрагменты уже не влезали.
const (
	fragmentMagic      byte = 0xF2
	fragmentHeaderSize      = 11
	// maxDirectDatagram — с какого размера пробуем отправить одной QUIC
	// датаграммой. Реальный лимит узнаём из quic.DatagramTooLargeError.
	maxDirectDatagram = 1400
	// defaultFragmentChunk — безопасный payload фрагмента, если лимит пути
	// неизвестен (стартовый QUIC MTU 1280).
	defaultFragmentChunk = 1100
	maxFragmentChunk     = 1500
	maxReassemblySets    = 128
	reassemblyTTL        = 30 * time.Second
	maxReassembledSize   = 65535
	reassemblyPruneEvery = time.Second
)

// fragmentBufPool переиспользует scratch-буфер под фрагмент. Отправитель
// (quic.Conn.SendDatagram) копирует payload в свой DatagramFrame до возврата,
// поэтому буфер можно сразу переиспользовать под следующий фрагмент.
var fragmentBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, fragmentHeaderSize+maxFragmentChunk)
		return &b
	},
}

type fragmentSet struct {
	created time.Time
	count   uint16
	chunk   int
	buf     []byte
	seen    []bool
	size    int
	got     int
}

// datagramReassembler собирает фрагменты одного QUIC-соединения.
type datagramReassembler struct {
	mu        sync.Mutex
	sets      map[uint32]*fragmentSet
	lastPrune time.Time
}

func newDatagramReassembler() *datagramReassembler {
	return &datagramReassembler{sets: make(map[uint32]*fragmentSet)}
}

// fragmentEach режет data на фрагменты с общим id и отдаёт каждый в fn.
// fn обязан скопировать данные, если хочет сохранить их после возврата.
func fragmentEach(id uint32, data []byte, chunk int, fn func([]byte) error) error {
	if chunk <= 0 {
		chunk = defaultFragmentChunk
	}
	if chunk > maxFragmentChunk {
		chunk = maxFragmentChunk
	}
	count := (len(data) + chunk - 1) / chunk
	if count == 0 {
		return nil
	}
	if count > 0xffff {
		return fmt.Errorf("too many fragments: %d", count)
	}

	bp := fragmentBufPool.Get().(*[]byte)
	buf := *bp
	need := fragmentHeaderSize + chunk
	if cap(buf) < need {
		buf = make([]byte, need)
		*bp = buf
	}
	buf = buf[:need]
	defer fragmentBufPool.Put(bp)

	for i := 0; i < count; i++ {
		start := i * chunk
		end := start + chunk
		if end > len(data) {
			end = len(data)
		}
		n := fragmentHeaderSize + end - start
		buf[0] = fragmentMagic
		binary.BigEndian.PutUint16(buf[1:3], uint16(i))
		binary.BigEndian.PutUint16(buf[3:5], uint16(count))
		binary.BigEndian.PutUint32(buf[5:9], id)
		binary.BigEndian.PutUint16(buf[9:11], uint16(chunk))
		copy(buf[fragmentHeaderSize:n], data[start:end])
		if err := fn(buf[:n]); err != nil {
			return err
		}
	}
	return nil
}

// fragmentDatagram режет data на фрагменты с общим id. Оставлен для тестов:
// в hot path используется sendFragments без аллокации [][]byte.
func fragmentDatagram(id uint32, data []byte, chunk int) [][]byte {
	var out [][]byte
	_ = fragmentEach(id, data, chunk, func(b []byte) error {
		out = append(out, append([]byte(nil), b...))
		return nil
	})
	return out
}

// sendFragments режет data и отправляет каждый фрагмент через send.
func sendFragments(send func([]byte) error, id uint32, data []byte, chunk int) error {
	return fragmentEach(id, data, chunk, send)
}

// add принимает один фрагмент. ready=true означает, что пакет собран целиком.
func (r *datagramReassembler) add(data []byte) (packet []byte, ready bool, err error) {
	if len(data) < fragmentHeaderSize || data[0] != fragmentMagic {
		return nil, false, fmt.Errorf("not a fragment")
	}
	idx := binary.BigEndian.Uint16(data[1:3])
	count := binary.BigEndian.Uint16(data[3:5])
	id := binary.BigEndian.Uint32(data[5:9])
	chunk := int(binary.BigEndian.Uint16(data[9:11]))
	if count == 0 || idx >= count || chunk <= 0 || chunk > maxFragmentChunk {
		return nil, false, fmt.Errorf("invalid fragment %d/%d chunk=%d", idx, count, chunk)
	}
	payload := data[fragmentHeaderSize:]

	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	if len(r.sets) >= maxReassemblySets || now.Sub(r.lastPrune) >= reassemblyPruneEvery {
		r.pruneLocked(now)
		r.lastPrune = now
	}

	set := r.sets[id]
	if set == nil {
		if len(r.sets) >= maxReassemblySets {
			return nil, false, fmt.Errorf("too many incomplete datagrams")
		}
		total := int(count) * chunk
		if total > maxReassembledSize {
			return nil, false, fmt.Errorf("reassembled datagram too large: %d", total)
		}
		set = &fragmentSet{
			created: now,
			count:   count,
			chunk:   chunk,
			buf:     make([]byte, total),
			seen:    make([]bool, count),
		}
		r.sets[id] = set
	}
	if set.count != count || set.chunk != chunk {
		delete(r.sets, id)
		return nil, false, fmt.Errorf("fragment layout mismatch for datagram %d", id)
	}
	if set.seen[idx] {
		return nil, false, nil // дубликат: QUIC может доставить повторно
	}
	// Все фрагменты кроме последнего должны быть полными: только тогда
	// buf[:size] после сборки совпадает с исходным пакетом.
	if idx < count-1 && len(payload) != chunk {
		delete(r.sets, id)
		return nil, false, fmt.Errorf("short fragment %d/%d", idx, count)
	}
	if len(payload) > chunk {
		delete(r.sets, id)
		return nil, false, fmt.Errorf("fragment %d too large", idx)
	}

	off := int(idx) * chunk
	copy(set.buf[off:off+len(payload)], payload)
	set.seen[idx] = true
	set.size += len(payload)
	set.got++

	if set.got != int(count) {
		return nil, false, nil
	}

	// set.buf уже содержит весь пакет по смещениям: финальная копия не нужна.
	// Вызывающий (session engine) копирует его в pooled-сообщение роутера.
	out := set.buf[:set.size]
	delete(r.sets, id)
	return out, true, nil
}

// pruneLocked вызывается не чаще раза в секунду (или при переполнении),
// а не на каждом фрагменте: иначе map обходится 100k раз в секунду.
func (r *datagramReassembler) pruneLocked(now time.Time) {
	for id, set := range r.sets {
		if now.Sub(set.created) > reassemblyTTL {
			delete(r.sets, id)
		}
	}
}
