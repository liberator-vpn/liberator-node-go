package peersmanager

import (
	"context"
	"errors"
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
		usage:       make(map[uint32]*usageAgg),
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
	if pm.usage == nil {
		pm.usage = make(map[uint32]*usageAgg)
	}
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

// UsageSnapshot возвращает срез накопленных дельт без их списания.
// Списание делает CommitUsage только после успешной отправки в API, иначе
// неудачный push безвозвратно терял бы биллинг.
func (pm *PeersManager) UsageSnapshot() []Usage {
	pm.usageMu.Lock()
	defer pm.usageMu.Unlock()

	out := make([]Usage, 0, len(pm.usage))
	for ip, a := range pm.usage {
		out = append(out, Usage{VirtualIP: ip, Up: a.up, Down: a.down})
	}
	return out
}

// CommitUsage вычитает ровно те дельты, которые были отправлены в API.
// Дельты, накопленные за время HTTP-запроса, остаются в карте.
func (pm *PeersManager) CommitUsage(committed []Usage) {
	pm.usageMu.Lock()
	defer pm.usageMu.Unlock()

	for _, u := range committed {
		a := pm.usage[u.VirtualIP]
		if a == nil {
			continue
		}
		if u.Up >= a.up {
			a.up = 0
		} else {
			a.up -= u.Up
		}
		if u.Down >= a.down {
			a.down = 0
		} else {
			a.down -= u.Down
		}
	}
}

// PruneUsage удаляет записи без неотправленных байт, для которых keep(ip)
// вернул false. Нужен, чтобы карта не росла вечно после ухода клиентов.
func (pm *PeersManager) PruneUsage(keep func(ip uint32) bool) {
	pm.usageMu.Lock()
	defer pm.usageMu.Unlock()

	for ip, a := range pm.usage {
		if a.up != 0 || a.down != 0 {
			continue
		}
		if !keep(ip) {
			delete(pm.usage, ip)
		}
	}
}

// DrainUsage возвращает накопленные дельты и сбрасывает счётчики.
// Оставлен для совместимости; в control-plane цикле используется
// UsageSnapshot + CommitUsage.
func (pm *PeersManager) DrainUsage() []Usage {
	out := pm.UsageSnapshot()
	pm.CommitUsage(out)
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
	var errs []error
	for _, c := range clients {
		want[c.VirtualIP] = struct{}{}
		if err := trp.CreatePeer(&model.Peer{
			Protocol:       c.Protocol,
			Name:           c.Name,
			Auth:           c.Auth,
			VirtualIP:      c.VirtualIP,
			AwgPublicKey:   c.AwgPublicKey,
			TrafficLimitGb: c.TrafficLimitGb,
			SpeedLimitMbps: c.SpeedLimitMbps,
		}); err != nil {
			// Один битый клиент не должен блокировать реконсиляцию остальных
			// и удаление уже исчезнувших. Ошибка вернётся наверх после прохода.
			errs = append(errs, fmt.Errorf("provision client %s: %w", netutils.Uint32ToIPString(c.VirtualIP), err))
		}
	}

	pm.mu.Lock()
	prev := pm.provisioned[transportName]
	if prev == nil {
		prev = make(map[uint32]struct{})
		pm.provisioned[transportName] = prev
	}
	var toKick []uint32
	for ip := range prev {
		if _, keep := want[ip]; keep {
			continue
		}
		toKick = append(toKick, ip)
		delete(prev, ip)
	}
	for ip := range want {
		prev[ip] = struct{}{}
	}
	pm.mu.Unlock()

	// KickPeer может трогать routing table/транспорт — не держим pm.mu.
	for _, ip := range toKick {
		trp.KickPeer(ip)
	}
	return errors.Join(errs...)
}

// ActiveCount возвращает число провижинённых клиентов на транспорте.
func (pm *PeersManager) ActiveCount(transportName string) int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return len(pm.provisioned[transportName])
}

// ActiveCountAll — суммарное число динамически провижинённых клиентов по всем
// транспортам (heartbeat в API).
func (pm *PeersManager) ActiveCountAll() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	total := 0
	for _, ips := range pm.provisioned {
		total += len(ips)
	}
	return total
}
