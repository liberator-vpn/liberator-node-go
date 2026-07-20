package dgmessage

import (
	"encoding/binary"
	"fmt"
	"sync"
)

type HoleInfo struct {
	SrcIP    uint32
	DstIP    uint32
	SrcPort  uint16
	DstPort  uint16
	Protocol string
}

type DatagramMessage struct {
	Data      []byte
	IPVersion int
	HoleInfo  HoleInfo

	pool *dgMessagePoolImpl
}

type DGMessagePool interface {
	NewMessageCopyFrom(data []byte) (*DatagramMessage, error)
}

type dgMessagePoolImpl struct {
	pool    sync.Pool
	maxSize int
}

func NewDGMessagePool(maxSize int) DGMessagePool {
	return &dgMessagePoolImpl{
		maxSize: maxSize,
		pool: sync.Pool{
			New: func() any {
				msg := &DatagramMessage{
					Data:      make([]byte, 0, maxSize),
					IPVersion: 4,
				}
				msg.HoleInfo.SrcIP = 0
				msg.HoleInfo.DstIP = 0
				return msg
			},
		},
	}
}

func (dgpool *dgMessagePoolImpl) NewMessageCopyFrom(copyFrom []byte) (*DatagramMessage, error) {
	if len(copyFrom) < 20 {
		return nil, fmt.Errorf("packet too small for IPv4")
	}
	if (copyFrom[0] >> 4) != 4 {
		return nil, fmt.Errorf("only ipv4 is supported")
	}

	if len(copyFrom) > dgpool.maxSize {
		return nil, fmt.Errorf("packet size exceeds pool capacity")
	}

	ihl := int(copyFrom[0]&0x0F) * 4
	var protocol string
	var srcPort, dstPort uint16

	switch copyFrom[9] {
	case 6: // TCP
		if len(copyFrom) < ihl+14 {
			return nil, fmt.Errorf("packet too small for TCP")
		}
		protocol = "tcp"
		srcPort = binary.BigEndian.Uint16(copyFrom[ihl : ihl+2])
		dstPort = binary.BigEndian.Uint16(copyFrom[ihl+2 : ihl+4])
	case 17: // UDP
		if len(copyFrom) < ihl+8 {
			return nil, fmt.Errorf("packet too small for UDP")
		}
		protocol = "udp"
		srcPort = binary.BigEndian.Uint16(copyFrom[ihl : ihl+2])
		dstPort = binary.BigEndian.Uint16(copyFrom[ihl+2 : ihl+4])
	case 1: // ICMP
		protocol = "icmp"
	default:
		return nil, fmt.Errorf("unsupported L4 protocol")
	}

	// 2. Берем ОЧИЩЕННЫЙ готовый объект из пула
	msg := dgpool.pool.Get().(*DatagramMessage)
	msg.pool = dgpool

	msg.Data = msg.Data[:len(copyFrom)]

	// Копируем данные напрямую в память объекта
	copy(msg.Data, copyFrom)

	// Заполняем превыделенные IP и порты
	msg.HoleInfo.SrcIP = binary.BigEndian.Uint32(copyFrom[12:16])
	msg.HoleInfo.DstIP = binary.BigEndian.Uint32(copyFrom[16:20])
	msg.HoleInfo.SrcPort = srcPort
	msg.HoleInfo.DstPort = dstPort
	msg.HoleInfo.Protocol = protocol

	return msg, nil
}

func (msg *DatagramMessage) Free() {
	if msg == nil || msg.pool == nil {
		return
	}

	// СБРОС: возвращаем длину в 0, но СОХРАНЯЕМ емкость (cap) для следующего пакета
	msg.Data = msg.Data[:0]
	msg.HoleInfo.Protocol = ""

	msg.pool.pool.Put(msg)
}
