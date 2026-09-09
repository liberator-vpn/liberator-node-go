package peersmanager

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/liberator-vpn/liberator-node-go/internal/appconfig"
	"github.com/liberator-vpn/liberator-node-go/internal/utils/netutils"
	"github.com/liberator-vpn/liberator-node-go/pkg/model"
	"github.com/liberator-vpn/liberator-node-go/pkg/transport"
)

// Usage — накопленная дельта трафика по virtual IP (для пуша в API billing).
type Usage struct {
	VirtualIP uint32
	Up        uint64 // байты, присланные клиентом (upload)
	Down      uint64 // байты, отправленные клиенту (download)
}

// PeersManager приводит транспорты к желаемому набору клиентов из state API.
// Нода ничего не аллоцирует и не хранит в БД.
type PeersManager struct {
	ctx context.Context

	mu          sync.RWMutex
	transports  map[string]transport.Transport
	provisioned map[string]map[uint32]struct{} // transportName -> virtual IPs

	usageMu sync.Mutex
	usage   map[uint32]*usageAgg
}

type usageAgg struct {
	up       uint64
	down     uint64
	lastSeen time.Time
}

func New(ctx context.Context) *PeersManager {
	return &PeersManager{
		ctx:         ctx,
		transports:  make(map[string]transport.Transport),
		provisioned: make(map[string]map[uint32]struct{}),
	}
}

// StartUsageCollector слушает дельты транспортов и копит их по virtual IP.
func (pm *PeersManager) StartUsageCollector(ctx context.Context) {
	pm.mu.RLock()
	trs := make([]transport.Transport, 0, len(pm.transports))
	for _, t := range pm.transports {
		trs = append(trs, t)
	}
	pm.mu.RUnlock()
	pm.usageMu.Lock()
	pm.usage = make(map[uint32]*usageAgg)
	pm.usageMu.Unlock()

	for _, t := range trs {
		go pm.collect(ctx, t)
	}
}

func (pm *PeersManager) collect(ctx context.Context, t transport.Transport) {
	for {
		select {
		case <-ctx.Done():
			return
		case s, ok := <-t.DeltaChan():
			if !ok {
				return
			}
			pm.usageMu.Lock()
			a := pm.usage[s.VirtualIP]
			if a == nil {
				a = &usageAgg{}
				pm.usage[s.VirtualIP] = a
			}
			a.up += s.DeltaFromPeer
			a.down += s.DeltaToPeer
			if !s.LastSeen.IsZero() {
				a.lastSeen = s.LastSeen
			}
			pm.usageMu.Unlock()
		}
	}
}

// DrainUsage возвращает накопленные дельты и сбрасывает счётчики.
func (pm *PeersManager) DrainUsage() []Usage {
	pm.usageMu.Lock()
	defer pm.usageMu.Unlock()

	out := make([]Usage, 0, len(pm.usage))
	for ip, a := range pm.usage {
		out = append(out, Usage{VirtualIP: ip, Up: a.up, Down: a.down})
		a.up, a.down = 0, 0
	}
	return out
}

// LastSeen возвращает время последней активности клиента по virtual IP.
func (pm *PeersManager) LastSeen(ip uint32) (time.Time, bool) {
	pm.usageMu.Lock()
	defer pm.usageMu.Unlock()
	a, ok := pm.usage[ip]
	if !ok {
		return time.Time{}, false
	}
	return a.lastSeen, true
}

// AliveWithin возвращает virtual IP тех клиентов, чья активность не старше window.
func (pm *PeersManager) AliveWithin(window time.Duration) []uint32 {
	pm.usageMu.Lock()
	defer pm.usageMu.Unlock()

	cut := time.Now().Add(-window)
	out := make([]uint32, 0, len(pm.usage))
	for ip, a := range pm.usage {
		if !a.lastSeen.IsZero() && a.lastSeen.After(cut) {
			out = append(out, ip)
		}
	}
	return out
}

// RegisterTransport регистрирует транспорт для провижина/сбора usage.
func (pm *PeersManager) RegisterTransport(name string, trp transport.Transport) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.transports[name] = trp
	if _, ok := pm.provisioned[name]; !ok {
		pm.provisioned[name] = make(map[uint32]struct{})
	}
}

// ReconcileClients приводит транспорт к желаемому набору клиентов: создаёт
// недостающих, обновляет лимиты существующих и удаляет исчезнувших.
func (pm *PeersManager) ReconcileClients(ctx context.Context, transportName string, clients []appconfig.ClientConfig) error {
	pm.mu.RLock()
	trp, ok := pm.transports[transportName]
	pm.mu.RUnlock()
	if !ok {
		return fmt.Errorf("transport with name %q not found", transportName)
	}

	want := make(map[uint32]struct{}, len(clients))
	for _, c := range clients {
		want[c.VirtualIP] = struct{}{}
		if err := trp.CreatePeer(&model.Peer{
			VirtualIP:      c.VirtualIP,
			AwgPublicKey:   c.AwgPublicKey,
			TrafficLimitGb: c.TrafficLimitGb,
			SpeedLimitMbps: c.SpeedLimitMbps,
		}); err != nil {
			return fmt.Errorf("provision client %s: %w", netutils.Uint32ToIPString(c.VirtualIP), err)
		}
	}

	pm.mu.Lock()
	prev := pm.provisioned[transportName]
	if prev == nil {
		prev = make(map[uint32]struct{})
		pm.provisioned[transportName] = prev
	}
	for ip := range prev {
		if _, keep := want[ip]; keep {
			continue
		}
		trp.KickPeer(ip)
		delete(prev, ip)
	}
	for ip := range want {
		prev[ip] = struct{}{}
	}
	pm.mu.Unlock()
	return nil
}

// ActiveCount возвращает число провижинённых клиентов на транспорте.
func (pm *PeersManager) ActiveCount(transportName string) int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return len(pm.provisioned[transportName])
}
