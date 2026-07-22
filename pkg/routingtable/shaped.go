package routingtable

import (
	"context"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// Static check
var _ RoutingObject = (*ShapedRoute)(nil)

type ShapedRoute struct {
	ctx        context.Context
	underlying RoutingObject

	queue   chan []byte
	limiter *rate.Limiter

	totalLimit atomic.Uint64
	limited    bool
}

// speedLimit = 0 means no speed limiting
// trafficLimit = 0 means no traffic limit
func NewShapedRoute(obj RoutingObject, speedLimit uint64, trafficLimit uint64) *ShapedRoute {
	sr := &ShapedRoute{
		ctx:        obj.Context(),
		underlying: obj,
		totalLimit: atomic.Uint64{},
		limited:    trafficLimit > 0,
	}
	sr.totalLimit.Add(trafficLimit)

	if speedLimit > 0 {
		sr.limiter = rate.NewLimiter(rate.Limit(speedLimit), 256*1500)
		sr.queue = make(chan []byte, 500)
		go sr.startWorker()
	}

	return sr
}

func (sr *ShapedRoute) GetNodeID() string        { return sr.underlying.GetNodeID() }
func (sr *ShapedRoute) GetVirtualIP() uint32     { return sr.underlying.GetVirtualIP() }
func (sr *ShapedRoute) Context() context.Context { return sr.ctx }
func (sr *ShapedRoute) SendDatagram(data []byte) error {
	sr.PushLimited(data)
	return nil
}

func (sr *ShapedRoute) PushLimited(data []byte) bool {
	select {
	case <-sr.ctx.Done():
		return false
	case sr.queue <- data:
		return true
	default:
		return false
	}
}
func (sr *ShapedRoute) IsAllowed(packetSize uint64) bool {
	if sr.limiter == nil {
		return true
	}
	return sr.limiter.AllowN(time.Now(), int(packetSize))
}
func (sr *ShapedRoute) startWorker() {
	defer func() {
		close(sr.queue)
	}()

	for {
		select {
		case <-sr.ctx.Done():
			return
		case data, ok := <-sr.queue:
			if !ok {
				return
			}
			packetSize := len(data)

			err := sr.limiter.WaitN(sr.ctx, packetSize)
			if err != nil {
				return // Контекст закрыт
			}
			sr.underlying.SendDatagram(data)
		}
	}
}
