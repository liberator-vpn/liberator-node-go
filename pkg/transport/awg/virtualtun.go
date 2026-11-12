package awg

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/liberator-vpn/liberator-node-go/internal/metrics"
	"github.com/liberator-vpn/liberator-node-go/internal/utils/safemap"
	"github.com/liberator-vpn/liberator-node-go/pkg/transport"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// ---------------------------------------------------------
// 2. Адаптер TUN -> Каналы
// ---------------------------------------------------------

type ChannelTun struct {
	ctx      context.Context
	in       <-chan []byte
	router   transport.Router
	mtu      int
	protocol string

	events    chan tun.Event
	closeOnce sync.Once

	peers safemap.Safemap[uint32, *AWGPeer] // IP -> Peer (нужно для обновления lastSeen)
}

var _ tun.Device = (*ChannelTun)(nil)

func NewChannelTun(ctx context.Context, in <-chan []byte, router transport.Router, mtu int, protocol string) *ChannelTun {
	return &ChannelTun{
		ctx:      ctx,
		in:       in,
		router:   router,
		events:   make(chan tun.Event, 1),
		peers:    safemap.New[uint32, *AWGPeer](),
		mtu:      mtu,
		protocol: protocol,
	}
}

func (t *ChannelTun) File() *os.File        { return nil }
func (t *ChannelTun) Name() (string, error) { return "liberator-awg-channel", nil }
func (t *ChannelTun) BatchSize() int        { return 128 }

// Close закрывает канал событий: Device.Close() ждет RoutineTUNEventReader, а тот
// висит в range по Events(). Раньше здесь на каждый вызов отдавался новый канал,
// который никто не закрывал, и awgDevice.Close() не возвращался никогда.
func (t *ChannelTun) Close() error {
	t.closeOnce.Do(func() { close(t.events) })
	return nil
}

func (t *ChannelTun) Events() <-chan tun.Event { return t.events }

func (t *ChannelTun) MTU() (int, error) { return t.mtu, nil }

func (t *ChannelTun) Write(bufs [][]byte, offset int) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}

	now := time.Now()

	// n — число буферов, реально принятых к обработке. amneziawg-go
	// интерпретирует возвращённое значение как «сколько пакетов записано»,
	// поэтому жёсткий 0 раньше выглядел как 100% потерь на приёме.
	c := int(0)
	for _, buf := range bufs {
		pkt := buf[offset:]

		msg, err := t.router.NewMessageCopyFrom(pkt)
		if err != nil {
			continue
		}
		metrics.ObserveTraffic(metrics.DirIn, metrics.PeerClient, t.protocol, len(pkt))
		// ОБНОВЛЯЕМ lastSeen (критически важно для watchdog)
		if peer, ok := t.peers.Get(msg.HoleInfo.SrcIP); ok {
			peer.TouchLastSeen(now)
			peer.totalFromPeer.Add(uint64(len(pkt)))
		}

		t.router.HandleTransportPacket(msg)
		c++
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
				// Если набрали мало пакетов, уступаем квант времени CPU (разрешаем батчинг)
				if n < 4 {
					runtime.Gosched()
					// Делаем еще одну быструю попытку вычитать из канала
					select {
					case pkt2, ok2 := <-t.in:
						if !ok2 || len(pkt2) == 0 {
							return n, nil
						}
						if len(pkt2) > len(bufs[n])-offset {
							return n, nil
						}
						copy(bufs[n][offset:], pkt2)
						sizes[n] = len(pkt2)
						n++
						continue
					default:
					}
				}
				return n, nil
			}
		}
		return n, nil

	case <-t.ctx.Done():
		return 0, os.ErrClosed
	}
}
