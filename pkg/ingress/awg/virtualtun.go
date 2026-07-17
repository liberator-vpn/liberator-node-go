package awg

import (
	"context"
	"fmt"
	"liberator-node-go/internal/utils/routingtable"
	"liberator-node-go/internal/utils/safemap"
	"os"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/tun"
)

// ---------------------------------------------------------
// 2. Адаптер TUN -> Каналы
// ---------------------------------------------------------

type ChannelTun struct {
	ctx   context.Context
	out   chan<- *routingtable.DatagramMessage
	in    <-chan []byte
	peers safemap.Safemap[string, *AWGPeer] // IP.String() -> Peer (нужно для обновления lastSeen)

	mtu int
}

var _ tun.Device = (*ChannelTun)(nil)

func NewChannelTun(ctx context.Context, out chan<- *routingtable.DatagramMessage, in <-chan []byte, mtu int) *ChannelTun {
	return &ChannelTun{
		ctx:   ctx,
		out:   out,
		in:    in,
		peers: safemap.New[string, *AWGPeer](),
		mtu:   mtu,
	}
}

func (t *ChannelTun) File() *os.File        { return nil }
func (t *ChannelTun) Name() (string, error) { return "liberator-awg-channel", nil }
func (t *ChannelTun) Close() error          { return nil }
func (t *ChannelTun) BatchSize() int        { return 1 }

func (t *ChannelTun) Events() <-chan tun.Event {
	ch := make(chan tun.Event, 1)
	return ch
}

func (t *ChannelTun) MTU() (int, error) { return t.mtu, nil }

func (t *ChannelTun) Write(bufs [][]byte, offset int) (int, error) {
	if len(bufs) == 0 || len(bufs[0]) == 0 {
		return 0, nil
	}
	pkt := bufs[0][offset:]

	msg, err := routingtable.NewDatagramMessage(pkt)
	if err != nil {
		return 0, nil
	}

	// ОБНОВЛЯЕМ lastSeen (Критически важно для Watchdog)
	if peer, ok := t.peers.Get(msg.HoleInfo.SrcIP.String()); ok {
		peer.lastSeen = time.Now()
	}

	select {
	case t.out <- msg:
		return 1, nil
	case <-t.ctx.Done():
		return 0, os.ErrClosed
	}
}

func (t *ChannelTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case pkt := <-t.in:
		if len(pkt) == 0 {
			return 0, nil
		}
		if len(pkt) > len(bufs[0])-offset {
			return 0, fmt.Errorf("packet larger than MTU")
		}
		copy(bufs[0][offset:], pkt)
		sizes[0] = len(pkt)
		return 1, nil
	case <-t.ctx.Done():
		return 0, os.ErrClosed
	}
}
