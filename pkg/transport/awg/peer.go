package awg

import (
	"context"
	"sync/atomic"
	"time"
)

type AWGPeer struct {
	ctx        context.Context
	nodeID     string
	virtualIP  uint32
	pubKey     string
	transport  *AWGTransport
	expiration *time.Time

	// lastSeenNanos — время последней активности (unix ns). Атомик, потому
	// что пишется из горячего пути ChannelTun.Write, а читается watchdog'ом
	// и отчётом alive из другой горутины.
	lastSeenNanos atomic.Int64

	totalToPeer   atomic.Uint64
	totalFromPeer atomic.Uint64
}

func NewAWGPeer(ctx context.Context, nodeID string, ip uint32, pubKey string, transport *AWGTransport, expiration *time.Time) *AWGPeer {
	p := &AWGPeer{
		ctx:        ctx,
		nodeID:     nodeID,
		virtualIP:  ip,
		pubKey:     pubKey,
		transport:  transport,
		expiration: expiration,
	}
	p.lastSeenNanos.Store(time.Now().UnixNano())
	return p
}

// --- Реализация интерфейса routingtable.RoutingObject ---

func (p *AWGPeer) GetNodeID() string        { return p.nodeID }
func (p *AWGPeer) GetVirtualIP() uint32     { return p.virtualIP }
func (p *AWGPeer) Context() context.Context { return p.ctx }

// LastSeen возвращает время последней замеченной активности пира.
func (p *AWGPeer) LastSeen() time.Time {
	return time.Unix(0, p.lastSeenNanos.Load())
}

// TouchLastSeen отмечает активность пира. Обновляем не чаще раза в секунду:
// значение нужно watchdog'у и alive-отчёту (окно — минуты), а запись атомика
// на каждый пакет — лишний cache line ping-pong на горячем пути.
func (p *AWGPeer) TouchLastSeen(now time.Time) {
	prev := p.lastSeenNanos.Load()
	if now.UnixNano()-prev < int64(time.Second) {
		return
	}
	p.lastSeenNanos.Store(now.UnixNano())
}

func (p *AWGPeer) SendDatagram(data []byte) error {
	p.totalToPeer.Add(uint64(len(data)))
	return p.transport.writePacket(data)
}

func (p *AWGPeer) Close() {
	// Для AWG физическое закрытие происходит через удаление пира из ядра
}

// snapshotStats снимает согласованный срез счётчиков и lastSeen.
// Счётчики обнуляем до чтения lastSeen, чтобы отданная дельта не оказалась
// «старее» lastSeen (иначе живой клиент мог выглядеть мёртвым).
func (p *AWGPeer) snapshotStats() (toPeer, fromPeer uint64, lastSeen time.Time) {
	toPeer = p.totalToPeer.Swap(0)
	fromPeer = p.totalFromPeer.Swap(0)
	lastSeen = p.LastSeen()
	return toPeer, fromPeer, lastSeen
}
