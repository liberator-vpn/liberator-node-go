package dgmessage

import (
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/liberator-vpn/liberator-node-go/internal/metrics"
)

// Headroom — место перед IP-пакетом под virtio-net заголовок TUN. Благодаря
// ему iface.writeLoop может отдавать буфер сообщения в TUN.Write напрямую,
// без копирования в отдельный flatBuffer.
const Headroom = 10

// minRawCap — capacity буфера сообщения. maxSize ограничивает размер
// принимаемого пакета (MTU + запас), а rawCap даёт amneziawg-go/tun
// запас для handleGRO: он склеивает TCP-пакеты через append в этот же
// буфер. С 4 КБ GRO склеивал ~3 пакета и писал в TUN почти по одному
// пакету; 64 КБ возвращает старое поведение flatBuffer, но без копии.
const minRawCap = 65535

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

	// raw — весь буфер: raw[:Headroom] — headroom, raw[Headroom:] — данные.
	raw []byte

	// createdAt фиксирует момент появления пакета (unix ns) для метрики времени
	// жизни. Заполняется только для сэмплированных пакетов (1 из 256), чтобы
	// не тратить time.Now() и Observe на каждый пакет.
	createdAt int64

	pool *dgMessagePoolImpl
}

type DGMessagePool interface {
	NewMessageCopyFrom(data []byte) (*DatagramMessage, error)
}

type dgMessagePoolImpl struct {
	pool    sync.Pool
	maxSize int
}

// lifetimeSample — счётчик для сэмплирования метрики packet_lifetime.
var lifetimeSample atomic.Uint64

func NewDGMessagePool(maxSize int) DGMessagePool {
	if maxSize <= 0 {
		maxSize = 2048
	}
	rawCap := maxSize
	if rawCap < minRawCap {
		rawCap = minRawCap
	}
	return &dgMessagePoolImpl{
		maxSize: maxSize,
		pool: sync.Pool{
			New: func() any {
				raw := make([]byte, Headroom+rawCap)
				msg := &DatagramMessage{
					Data:      raw[Headroom:Headroom],
					raw:       raw,
					IPVersion: 4,
				}
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

	// Берём очищенный готовый объект из пула.
	msg := dgpool.pool.Get().(*DatagramMessage)
	msg.pool = dgpool
	msg.createdAt = 0
	if lifetimeSample.Add(1)&255 == 0 {
		msg.createdAt = time.Now().UnixNano()
	}

	msg.Data = msg.raw[Headroom : Headroom+len(copyFrom)]

	// Копируем данные напрямую в память объекта.
	copy(msg.Data, copyFrom)

	// Заполняем предвыделенные IP и порты.
	msg.HoleInfo.SrcIP = binary.BigEndian.Uint32(copyFrom[12:16])
	msg.HoleInfo.DstIP = binary.BigEndian.Uint32(copyFrom[16:20])
	msg.HoleInfo.SrcPort = srcPort
	msg.HoleInfo.DstPort = dstPort
	msg.HoleInfo.Protocol = protocol

	return msg, nil
}

// Raw возвращает полный буфер сообщения: raw[Headroom:Headroom+len(Data)] —
// IP-пакет, raw[:Headroom] — место под virtio-заголовок.
func (msg *DatagramMessage) Raw() []byte {
	return msg.raw
}

func (msg *DatagramMessage) Free() {
	if msg == nil || msg.pool == nil {
		return
	}

	if msg.createdAt != 0 {
		metrics.ObservePacketLifetime(time.Duration(time.Now().UnixNano() - msg.createdAt))
	}

	// Сбрасываем длину, но сохраняем capacity для следующего пакета.
	msg.Data = msg.raw[Headroom:Headroom]
	msg.HoleInfo.Protocol = ""
	msg.createdAt = 0

	msg.pool.pool.Put(msg)
}
