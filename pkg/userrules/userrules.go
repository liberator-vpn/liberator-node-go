// Package userrules — таблица правил интернет-выхода пользователей
// (аналог routingtable, но по префиксам назначения, а не по virtual IP).
// Данные живут здесь, роутер лишь делает Lookup для решения об exit.
package userrules

import (
	"errors"
	"net"
	"sync"

	"github.com/liberator-vpn/liberator-node-go/internal/utils/netutils"
)

var errIPv6NotSupported = errors.New("userrules: only ipv4 prefixes are supported")

type rule struct {
	base uint32 // сеть (IP & mask)
	mask uint32 // сетевая маска
	exit string // mesh endpoint ноды-выхода
}

// Entry — одна запись желаемого состояния egress: для клиента clientIP
// префикс prefixCIDR должен выходить через ноду exit.
type Entry struct {
	ClientIP   uint32
	PrefixCIDR string
	Exit       string
}

// UserRules хранит для каждого клиента (src virtual IP) список правил
// (prefix dst -> exit) и отвечает на lookup по longest-prefix.
type UserRules struct {
	mu sync.RWMutex
	m  map[uint32][]rule
}

func New() *UserRules {
	return &UserRules{m: make(map[uint32][]rule)}
}

// parseRule превращает CIDR в внутреннее представление.
func parseRule(prefixCIDR, exit string) (rule, error) {
	_, ipnet, err := net.ParseCIDR(prefixCIDR)
	if err != nil {
		return rule{}, err
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 || ones > 32 {
		return rule{}, errIPv6NotSupported
	}
	maskB := net.CIDRMask(ones, 32)
	maskU := uint32(maskB[0])<<24 | uint32(maskB[1])<<16 | uint32(maskB[2])<<8 | uint32(maskB[3])
	return rule{base: netutils.IPToUint32(ipnet.IP) & maskU, mask: maskU, exit: exit}, nil
}

// Set добавляет клиенту правило выхода для префикса (CIDR). exit == "" — запись
// не нужна (локальный NAT), вызывающий просто не добавляет её.
func (r *UserRules) Set(clientIP uint32, prefixCIDR, exit string) error {
	rl, err := parseRule(prefixCIDR, exit)
	if err != nil {
		return err
	}

	r.mu.Lock()
	r.m[clientIP] = append(r.m[clientIP], rl)
	r.mu.Unlock()
	return nil
}

// ReplaceAll атомарно заменяет всю таблицу новым набором правил. Так между
// очисткой и заполнением нет окна, в котором egress-трафик уходит в локальный
// NAT. Возвращает число отброшенных невалидных записей.
func (r *UserRules) ReplaceAll(entries []Entry) int {
	next := make(map[uint32][]rule, len(entries)/4+1)
	invalid := 0
	for _, e := range entries {
		rl, err := parseRule(e.PrefixCIDR, e.Exit)
		if err != nil {
			invalid++
			continue
		}
		next[e.ClientIP] = append(next[e.ClientIP], rl)
	}

	r.mu.Lock()
	r.m = next
	r.mu.Unlock()
	return invalid
}

// Clear сбрасывает все правила (реконсилится за цикл).
func (r *UserRules) Clear() {
	r.mu.Lock()
	r.m = make(map[uint32][]rule)
	r.mu.Unlock()
}

// Lookup возвращает ноду-выход для (src client, dst) по longest-prefix.
// "" — локальный NAT.
func (r *UserRules) Lookup(src, dst uint32) string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	best := ""
	bestMask := uint32(0)
	for _, rl := range r.m[src] {
		if (dst&rl.mask) == rl.base && rl.mask > bestMask {
			best = rl.exit
			bestMask = rl.mask
		}
	}
	return best
}
