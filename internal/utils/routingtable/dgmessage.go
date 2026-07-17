package routingtable

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

type DGMessagePool interface {
	Get() *[]byte
	Put(*[]byte)
	NewMessageCopyFrom(data []byte) (*DatagramMessage, error)
}
type dgMessagePoolImpl struct {
	pool sync.Pool
}

func NewDGMessagePool(maxSize int) DGMessagePool {
	return &dgMessagePoolImpl{
		pool: sync.Pool{
			New: func() any {
				v := make([]byte, 0, maxSize)
				return &v
			},
		},
	}
}
func (dgpool *dgMessagePoolImpl) Get() *[]byte {
	return dgpool.pool.Get().(*[]byte)
}
func (dgpool *dgMessagePoolImpl) Put(x *[]byte) {
	*x = (*x)[:0]
	dgpool.pool.Put(x)
}

type DatagramMessage struct {
	Data      *[]byte
	IPVersion int
	HoleInfo  HoleInfo

	dgMessagePool DGMessagePool
}

func (dgpool *dgMessagePoolImpl) NewMessageCopyFrom(copyFrom []byte) (*DatagramMessage, error) {
	// 1. Берем указатель на слайс из пула
	bufPtr := dgpool.Get()

	// 2. ВАЛИДАЦИЯ ДО КОПИРОВАНИЯ (работаем с copyFrom, чтобы не трогать пул)
	if len(copyFrom) < 20 {
		dgpool.Put(bufPtr) // Возвращаем в пул, если пакет слишком мелкий
		return nil, fmt.Errorf("packet too small for IPv4")
	}
	if (copyFrom[0] >> 4) != 4 {
		dgpool.Put(bufPtr) // Возвращаем в пул, если это не IPv4
		return nil, fmt.Errorf("only ipv4 is supported")
	}

	// 3. БЫСТРОЕ ИЗВЛЕЧЕНИЕ ЗАГОЛОВКОВ ИЗ copyFrom (без аллокаций структур!)
	srcIP := net.IP(copyFrom[12:16])
	dstIP := net.IP(copyFrom[16:20])
	ihl := int(copyFrom[0]&0x0F) * 4

	var protocol string
	var srcPort, dstPort uint16

	switch copyFrom[9] { // Протокол на смещении 9
	case 6: // TCP
		if len(copyFrom) < ihl+14 {
			dgpool.Put(bufPtr)
			return nil, fmt.Errorf("packet too small for TCP")
		}
		protocol = "tcp"
		srcPort = binary.BigEndian.Uint16(copyFrom[ihl : ihl+2])
		dstPort = binary.BigEndian.Uint16(copyFrom[ihl+2 : ihl+4])
	case 17: // UDP
		if len(copyFrom) < ihl+8 {
			dgpool.Put(bufPtr)
			return nil, fmt.Errorf("packet too small for UDP")
		}
		protocol = "udp"
		srcPort = binary.BigEndian.Uint16(copyFrom[ihl : ihl+2])
		dstPort = binary.BigEndian.Uint16(copyFrom[ihl+2 : ihl+4])
	case 1: // ICMP
		protocol = "icmp"
	default:
		// Неизвестный протокол - дропаем и возвращаем буфер в пул
		dgpool.Put(bufPtr)
		return nil, fmt.Errorf("unsupported L4 protocol")
	}

	// 4. ТЕПЕРЬ КОПИРУЕМ (только если пакет на 100% валидный)
	// Делаем слайс нужной длины, указывающий на память из пула
	data := (*bufPtr)[:len(copyFrom)]
	copy(data, copyFrom)

	// 5. ВОЗВРАЩАЕМ СТРУКТУРУ (gopacket полностью исключен)
	// Обратите внимание: в Data мы сохраняем УКАЗАТЕЛЬ на слайс
	return &DatagramMessage{
		dgMessagePool: dgpool,
		Data:          &data,
		IPVersion:     4,
		HoleInfo: HoleInfo{
			SrcIP:    srcIP,
			DstIP:    dstIP,
			SrcPort:  srcPort,
			DstPort:  dstPort,
			Protocol: protocol,
		},
	}, nil
}
func (msg *DatagramMessage) Free() {
	msg.dgMessagePool.Put(msg.Data)
	msg.Data = nil
}
