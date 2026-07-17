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
	ctx         context.Context
	out         chan<- *routingtable.DatagramMessage
	in          <-chan []byte
	packetsPool routingtable.DGMessagePool
	peers       safemap.Safemap[string, *AWGPeer] // IP.String() -> Peer (нужно для обновления lastSeen)

	mtu int
}

var _ tun.Device = (*ChannelTun)(nil)

func NewChannelTun(ctx context.Context, out chan<- *routingtable.DatagramMessage, in <-chan []byte, packetsPool routingtable.DGMessagePool, mtu int) *ChannelTun {
	return &ChannelTun{
		ctx:         ctx,
		out:         out,
		in:          in,
		packetsPool: packetsPool,
		peers:       safemap.New[string, *AWGPeer](),
		mtu:         mtu,
	}
}

func (t *ChannelTun) File() *os.File        { return nil }
func (t *ChannelTun) Name() (string, error) { return "liberator-awg-channel", nil }
func (t *ChannelTun) Close() error          { return nil }
func (t *ChannelTun) BatchSize() int        { return 16 }

func (t *ChannelTun) Events() <-chan tun.Event {
	ch := make(chan tun.Event, 1)
	return ch
}

func (t *ChannelTun) MTU() (int, error) { return t.mtu, nil }

func (t *ChannelTun) Write(bufs [][]byte, offset int) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}
	c := int(0)
	for _, buf := range bufs {
		pkt := buf[offset:]

		msg, err := t.packetsPool.NewMessageCopyFrom(pkt)
		if err != nil {
			continue
		}
		// ОБНОВЛЯЕМ lastSeen (Критически важно для Watchdog)
		if peer, ok := t.peers.Get(msg.HoleInfo.SrcIP.String()); ok {
			peer.lastSeen = time.Now()
		}
		select {
		case t.out <- msg:
			c++
		case <-t.ctx.Done():
			return c, os.ErrClosed
		}
	}
	return c, nil
}

func (t *ChannelTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	// Ждём первый пакет
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
		n := 1

		// Пытаемся прочитать дополнительные пакеты, если есть место в буферах
		for i := 1; i < len(bufs); i++ {
			select {
			case pkt2 := <-t.in:
				if len(pkt2) == 0 {
					break
				}
				if len(pkt2) > len(bufs[i])-offset {
					// Если не влезает, возвращаем уже прочитанные
					return n, nil
				}
				copy(bufs[i][offset:], pkt2)
				sizes[i] = len(pkt2)
				n++
			default:
				// Больше пакетов нет – возвращаем то, что накопили
				return n, nil
			}
		}
		return n, nil

	case <-t.ctx.Done():
		return 0, os.ErrClosed
	}
}
