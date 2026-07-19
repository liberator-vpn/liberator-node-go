package router

import (
	"liberator-node-go/internal/utils/dgmessage"
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
	r.getWorker(packet.HoleInfo) <- datagramMessageInfo{
		Msg:  packet,
		From: fromTun,
	}
}
func (r *Router) HandleMeshPacket(packet *dgmessage.DatagramMessage) {
	r.getWorker(packet.HoleInfo) <- datagramMessageInfo{
		Msg:  packet,
		From: fromMesh,
	}
}
func (r *Router) HandleTransportPacket(packet *dgmessage.DatagramMessage) {
	r.getWorker(packet.HoleInfo) <- datagramMessageInfo{
		Msg:  packet,
		From: fromTransport,
	}
}

func (r *Router) getWorker(hi dgmessage.HoleInfo) chan datagramMessageInfo {
	// 1. Упорядочиваем IP и порты для симметричности
	ip1, ip2 := hi.SrcIP, hi.DstIP
	port1, port2 := hi.SrcPort, hi.DstPort
	if ip1 > ip2 || (ip1 == ip2 && port1 > port2) {
		ip1, ip2 = ip2, ip1
		port1, port2 = port2, port1
	}

	// 2. Комбинируем все поля в 64-битное значение
	// Используем большую константу для перемешивания (золотое сечение)
	var h uint64
	h = uint64(ip1)<<32 ^ uint64(ip2)
	h = h*0x9e3779b97f4a7c15 + uint64(port1)<<16 + uint64(port2)

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

	// 4. Вычисляем индекс воркера
	idx := hash % uint32(len(r.shardedWorkers))
	return r.shardedWorkers[idx]
}
