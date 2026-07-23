package routingtable

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/TexHik620953/liberator-node-go/internal/utils/dgmessage"
	"golang.org/x/time/rate"
)

// Static check
var _ RoutingObject = (*ShapedRoute)(nil)

type ShapedRoute struct {
	ctx        context.Context
	underlying RoutingObject

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
			return nil
		}
	}
	if !sr.speedLimited {
		err := sr.SendDatagram(packet.Data)
		if err != nil {
			packet.Free()
			return err
		}
		packet.Free()
	}

	select {
	case <-sr.ctx.Done():
		return sr.ctx.Err()
	case sr.queue <- packet:
		return nil
	default:
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
func (sr *ShapedRoute) startWorker() {
	defer func() {
		close(sr.queue)
	}()

	for {
		select {
		case <-sr.ctx.Done():
			return
		case packet, ok := <-sr.queue:
			if !ok {
				return
			}
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
