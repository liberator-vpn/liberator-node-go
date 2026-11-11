package xray

import "encoding/binary"

// rewriteIPv4Source меняет source IP пакета и обновляет checksum'ы.
func rewriteIPv4Source(data []byte, newSrc uint32) bool {
	return rewriteIPv4Address(data, &newSrc, nil)
}

// rewriteIPv4Destination меняет destination IP пакета и обновляет checksum'ы.
func rewriteIPv4Destination(data []byte, newDst uint32) bool {
	return rewriteIPv4Address(data, nil, &newDst)
}

func ipv4Source(data []byte) (uint32, bool) {
	if len(data) < 20 || data[0]>>4 != 4 {
		return 0, false
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || len(data) < ihl {
		return 0, false
	}
	return binary.BigEndian.Uint32(data[12:16]), true
}

func rewriteIPv4Address(data []byte, newSrc, newDst *uint32) bool {
	if len(data) < 20 || data[0]>>4 != 4 {
		return false
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || len(data) < ihl {
		return false
	}

	oldSrc := binary.BigEndian.Uint32(data[12:16])
	oldDst := binary.BigEndian.Uint32(data[16:20])

	if newSrc != nil {
		binary.BigEndian.PutUint32(data[12:16], *newSrc)
	}
	if newDst != nil {
		binary.BigEndian.PutUint32(data[16:20], *newDst)
	}

	// IP header checksum пересчитываем целиком — заголовок маленький.
	data[10], data[11] = 0, 0
	binary.BigEndian.PutUint16(data[10:12], checksum16(data[:ihl], 0))

	// L4 checksum меняем инкрементально: это работает и для первого
	// фрагмента, где нет всего TCP/UDP сегмента.
	proto := data[9]
	if proto != 6 && proto != 17 {
		return true // ICMP checksum не зависит от IP-адресов
	}
	fragOff := binary.BigEndian.Uint16(data[6:8]) & 0x1fff
	if fragOff != 0 {
		return true
	}
	l4 := data[ihl:]
	off := 16 // TCP
	if proto == 17 {
		off = 6 // UDP
	}
	if len(l4) < off+2 {
		return true
	}
	// UDP checksum == 0 означает «не считать»; не трогаем.
	if proto == 17 && binary.BigEndian.Uint16(l4[off:off+2]) == 0 {
		return true
	}

	sum := binary.BigEndian.Uint16(l4[off : off+2])
	if newSrc != nil {
		sum = checksumUpdate(sum, oldSrc, *newSrc)
	}
	if newDst != nil {
		sum = checksumUpdate(sum, oldDst, *newDst)
	}
	binary.BigEndian.PutUint16(l4[off:off+2], sum)
	return true
}

// checksumUpdate — RFC 1624: HC' = ~(~HC + ~m + m') для 32-битного адреса
// (две 16-битные пары).
func checksumUpdate(sum uint16, oldIP, newIP uint32) uint16 {
	sum = incremental(sum, uint16(oldIP>>16), uint16(newIP>>16))
	return incremental(sum, uint16(oldIP), uint16(newIP))
}

func incremental(sum, oldWord, newWord uint16) uint16 {
	acc := uint32(^sum) + uint32(^oldWord) + uint32(newWord)
	for acc>>16 != 0 {
		acc = (acc & 0xffff) + (acc >> 16)
	}
	return ^uint16(acc)
}

func checksum16(data []byte, initial uint32) uint16 {
	sum := initial
	for len(data) > 1 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
