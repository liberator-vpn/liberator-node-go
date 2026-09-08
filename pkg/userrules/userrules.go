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

// UserRules хранит для каждого клиента (src virtual IP) список правил
// (prefix dst -> exit) и отвечает на lookup по longest-prefix.
type UserRules struct {
	mu sync.RWMutex
	m  map[uint32][]rule
}

func New() *UserRules {
	return &UserRules{m: make(map[uint32][]rule)}
}

// Set добавляет клиенту правило выхода для префикса (CIDR). exit == "" — запись
// не нужна (локальный NAT), вызывающий просто не добавляет её.
func (r *UserRules) Set(clientIP uint32, prefixCIDR, exit string) error {
	_, ipnet, err := net.ParseCIDR(prefixCIDR)
	if err != nil {
		return err
	}
	ones, _ := ipnet.Mask.Size()
	if ones > 32 {
		return errIPv6NotSupported
	}
	maskB := net.CIDRMask(ones, 32)
	maskU := uint32(maskB[0])<<24 | uint32(maskB[1])<<16 | uint32(maskB[2])<<8 | uint32(maskB[3])

	r.mu.Lock()
	r.m[clientIP] = append(r.m[clientIP], rule{base: netutils.IPToUint32(ipnet.IP) & maskU, mask: maskU, exit: exit})
	r.mu.Unlock()
	return nil
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
