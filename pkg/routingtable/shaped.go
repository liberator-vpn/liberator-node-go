package routingtable

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/liberator-vpn/liberator-node-go/internal/utils/dgmessage"
	"golang.org/x/time/rate"
)

// Static check
var _ RoutingObject = (*ShapedRoute)(nil)

type ShapedRoute struct {
	ctx        context.Context
	underlying RoutingObject

	mu           sync.Mutex
	queue        chan *dgmessage.DatagramMessage
	limiter      *rate.Limiter
	speedLimited bool

	totalLimit     atomic.Int64
	trafficLimited bool
}

// speedLimit = 0 means no speed limiting
// trafficLimit = 0 means no traffic limit
func NewShapedRoute(obj RoutingObject, speedLimit *uint64, trafficLimit *uint64) *ShapedRoute {
	sr := &ShapedRoute{
		ctx:            obj.Context(),
		underlying:     obj,
		totalLimit:     atomic.Int64{},
		trafficLimited: trafficLimit != nil,
		speedLimited:   speedLimit != nil,
	}

	if trafficLimit != nil {
		sr.totalLimit.Add(int64(*trafficLimit))
	}

	if sr.speedLimited {
		sr.limiter = rate.NewLimiter(rate.Limit(*speedLimit), 256*1500)
		sr.queue = make(chan *dgmessage.DatagramMessage, 500)
		go sr.startWorker()
	}

	return sr
}

func (sr *ShapedRoute) GetNodeID() string        { return sr.underlying.GetNodeID() }
func (sr *ShapedRoute) GetVirtualIP() uint32     { return sr.underlying.GetVirtualIP() }
func (sr *ShapedRoute) Context() context.Context { return sr.ctx }
func (sr *ShapedRoute) SendDatagram(data []byte) error {
	return sr.underlying.SendDatagram(data)
}

func (sr *ShapedRoute) PushLimited(packet *dgmessage.DatagramMessage) error {
	if sr.trafficLimited {
		remains := sr.totalLimit.Add(-int64(len(packet.Data)))
		if remains < 0 {
			// Пакет не отправляем, но вернуть его в пул обязаны — иначе утечка.
			packet.Free()
			return nil
		}
	}
	if !sr.speedLimited {
		err := sr.SendDatagram(packet.Data)
		packet.Free()
		return err
	}

	select {
	case <-sr.ctx.Done():
		packet.Free()
		return sr.ctx.Err()
	case sr.queue <- packet:
		return nil
	default:
		// Очередь полна: дропаем пакет (шейпер не должен блокировать роутер),
		// но возвращаем его в пул.
		packet.Free()
		return nil
	}
}
func (sr *ShapedRoute) IsAllowed(packetSize uint64) bool {
	if sr.trafficLimited {
		remains := sr.totalLimit.Add(-int64(packetSize))
		if remains < 0 {
			return false
		}
	}

	if sr.speedLimited {
		return sr.limiter.AllowN(time.Now(), int(packetSize))
	}
	return true
}

// SetLimits обновляет лимиты «на лету». Возвращает false, если сменился сам
// режим лимитирования (появился/исчез лимит) — тогда маршрут надо пересоздать.
func (sr *ShapedRoute) SetLimits(speedLimit *uint64, trafficLimit *uint64) bool {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	if sr.speedLimited != (speedLimit != nil) || sr.trafficLimited != (trafficLimit != nil) {
		return false
	}
	if sr.speedLimited && sr.limiter != nil {
		sr.limiter.SetLimit(rate.Limit(*speedLimit))
	}
	if sr.trafficLimited && trafficLimit != nil {
		// totalLimit здесь — остаток; пересчитываем от нового значения.
		sr.totalLimit.Store(int64(*trafficLimit))
	}
	return true
}

func (sr *ShapedRoute) startWorker() {
	// Канал не закрываем: PushLimited может находиться в select с отправкой
	// в него в момент shutdown, а send в закрытый канал паникует. Вместо
	// этого по ctx просто выходим и освобождаем всё, что успело накопиться.
	defer func() {
		for {
			select {
			case packet := <-sr.queue:
				packet.Free()
			default:
				return
			}
		}
	}()

	for {
		select {
		case <-sr.ctx.Done():
			return
		case packet := <-sr.queue:
			packetSize := len(packet.Data)

			err := sr.limiter.WaitN(sr.ctx, packetSize)
			if err != nil {
				packet.Free()
				return // Контекст закрыт
			}
			sr.underlying.SendDatagram(packet.Data)
			packet.Free()
		}
	}
}
