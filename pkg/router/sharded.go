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
	worker := r.getWorker(packet.HoleInfo)
	select {
	case worker <- datagramMessageInfo{Msg: packet, From: from}:
	case <-r.ctx.Done():
		packet.Free()
	}
}

func (r *Router) getWorker(hi dgmessage.HoleInfo) chan datagramMessageInfo {
	// Направленный хэш: загрузка и скачивание одного TCP-соединения идут
	// в разные воркеры. Симметричный хэш складывал оба направления в один
	// воркер, и блокировка на отправке крупного download-потока задерживала
	// upload-ACK'и — TCP у отправителя схлопывал окно.
	var h uint64
	h = uint64(hi.SrcIP)<<32 ^ uint64(hi.DstIP)
	h = h*0x9e3779b97f4a7c15 + uint64(hi.SrcPort)<<16 + uint64(hi.DstPort)

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

	// 4. Вычисляем индекс воркера
	idx := hash % uint32(len(r.shardedWorkers))
	return r.shardedWorkers[idx]
}
