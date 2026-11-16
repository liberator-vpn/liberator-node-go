package router

import (
	"github.com/liberator-vpn/liberator-node-go/internal/utils/dgmessage"
)

type fromType = int

const (
	fromTransport fromType = 0
	fromTun       fromType = 1
	fromMesh      fromType = 2
)

type datagramMessageInfo struct {
	Msg  *dgmessage.DatagramMessage
	From fromType
}

func (r *Router) HandleTunPacket(packet *dgmessage.DatagramMessage) {
	r.enqueue(packet, fromTun)
}
func (r *Router) HandleMeshPacket(packet *dgmessage.DatagramMessage) {
	r.enqueue(packet, fromMesh)
}
func (r *Router) HandleTransportPacket(packet *dgmessage.DatagramMessage) {
	r.enqueue(packet, fromTransport)
}

// enqueue отдаёт пакет шардовому воркеру. Обычная отправка — backpressure
// для источника, но с выходом по ctx: на shutdown воркеры уже вышли и канал
// никто не читает, иначе TUN readLoop / QUIC-сессия / приём AWG висели бы
// навсегда, не давая приложению завершиться.
func (r *Router) enqueue(packet *dgmessage.DatagramMessage, from fromType) {
	worker := r.getWorker(packet.HoleInfo, from)
	select {
	case worker <- datagramMessageInfo{Msg: packet, From: from}:
	case <-r.ctx.Done():
		packet.Free()
	}
}

func (r *Router) getWorker(hi dgmessage.HoleInfo, from fromType) chan datagramMessageInfo {
	// Направленный хэш: все пакеты одного направления (один 5-tuple) идут
	// в один воркер и сохраняют порядок. Обратное направление — отдельный
	// поток, и его не нужно держать в том же воркере: при симметричном хэше
	// крупный download заполнял канал воркера, upload-пакеты вставали за ним,
	// AWG-receive блокировался и переполнял UDP-буфер.
	var h uint64
	h = uint64(hi.SrcIP)<<32 ^ uint64(hi.DstIP)
	h = h*0x9e3779b97f4a7c15 + uint64(hi.SrcPort)<<16 + uint64(hi.DstPort)

	// Добавляем протокол (используем первый байт)
	if len(hi.Protocol) > 0 {
		h ^= uint64(hi.Protocol[0]) << 48
	}

	// 3. Применяем скремблирующий алгоритм для получения равномерного распределения
	hash := uint32(h ^ (h >> 32)) // берём 32 младших бита
	hash ^= hash >> 16
	hash *= 0x85ebca6b
	hash ^= hash >> 13
	hash *= 0xc2b2ae35
	hash ^= hash >> 16

	// 4. Раздельные пулы: upload (из AWG) и download (из TUN/меша) не делят
	// воркеры. Иначе крупный download заполнял канал, upload-пакеты вставали
	// в очередь, AWG-receive блокировался и переполнял UDP-сокет.
	n := len(r.shardedWorkers)
	half := n / 2
	pool := r.shardedWorkers[half:]
	if from == fromTransport {
		pool = r.shardedWorkers[:half]
	}
	idx := hash % uint32(len(pool))
	return pool[idx]
}
