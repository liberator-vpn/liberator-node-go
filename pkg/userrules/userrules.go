// Package userrules — таблица правил интернет-выхода пользователей
// (аналог routingtable, но по префиксам назначения, а не по virtual IP).
// Данные живут здесь, роутер лишь делает Lookup для решения об exit/deny/direct.
package userrules

import (
	"errors"
	"math/bits"
	"net"
	"sync"

	"github.com/liberator-vpn/liberator-node-go/internal/utils/netutils"
)

var errIPv6NotSupported = errors.New("userrules: only ipv4 prefixes are supported")

const (
	ActionDirect = "direct"
	ActionDeny   = "deny"
	ActionExit   = "exit"
)

type rule struct {
	base          uint32 // сеть (IP & mask)
	mask          uint32 // сетевая маска
	action        string
	exit          string // mesh endpoint ноды-выхода (для action=exit)
	tier          int    // 0 = user, 1 = group
	groupPriority int32
	priority      int32
}

// Entry — одна запись желаемого состояния.
type Entry struct {
	ClientIP      uint32
	PrefixCIDR    string
	Action        string // exit | direct | deny; пусто = exit
	Exit          string
	Tier          int
	GroupPriority int32
	Priority      int32
}

type UserRules struct {
	mu sync.RWMutex
	m  map[uint32][]rule
}

func New() *UserRules {
	return &UserRules{m: make(map[uint32][]rule)}
}

// parseRule превращает CIDR в внутреннее представление.
func parseRule(prefixCIDR, action, exit string, tier int, groupPriority, priority int32) (rule, error) {
	_, ipnet, err := net.ParseCIDR(prefixCIDR)
	if err != nil {
		return rule{}, err
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 || ones > 32 {
		return rule{}, errIPv6NotSupported
	}
	if action == "" {
		action = ActionExit
	}
	maskB := net.CIDRMask(ones, 32)
	maskU := uint32(maskB[0])<<24 | uint32(maskB[1])<<16 | uint32(maskB[2])<<8 | uint32(maskB[3])
	return rule{
		base: netutils.IPToUint32(ipnet.IP) & maskU, mask: maskU,
		action: action, exit: exit, tier: tier,
		groupPriority: groupPriority, priority: priority,
	}, nil
}

// Set добавляет клиенту правило (по умолчанию action=exit).
func (r *UserRules) Set(clientIP uint32, prefixCIDR, exit string) error {
	rl, err := parseRule(prefixCIDR, ActionExit, exit, 0, 0, 0)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.m[clientIP] = append(r.m[clientIP], rl)
	r.mu.Unlock()
	return nil
}

// ReplaceAll атомарно заменяет всю таблицу новым набором правил.
func (r *UserRules) ReplaceAll(entries []Entry) int {
	next := make(map[uint32][]rule, len(entries)/4+1)
	invalid := 0
	for _, e := range entries {
		rl, err := parseRule(e.PrefixCIDR, e.Action, e.Exit, e.Tier, e.GroupPriority, e.Priority)
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

// Lookup возвращает действие и exit-endpoint для (src client, dst) по longest-prefix.
func (r *UserRules) Lookup(src, dst uint32) (action, exit string) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	bestAction := ActionDirect
	bestExit := ""
	bestTier := 1 << 30
	bestBits := -1
	bestGroupPriority := int32(1 << 30)
	bestPriority := int32(1 << 30)
	for _, rl := range r.m[src] {
		if (dst & rl.mask) != rl.base {
			continue
		}
		ruleBits := bits.OnesCount32(rl.mask)
		better := false
		switch {
		case rl.tier < bestTier:
			better = true
		case rl.tier > bestTier:
			better = false
		case ruleBits > bestBits:
			better = true
		case ruleBits < bestBits:
			better = false
		case rl.groupPriority < bestGroupPriority:
			better = true
		case rl.groupPriority > bestGroupPriority:
			better = false
		case rl.priority < bestPriority:
			better = true
		}
		if better {
			bestAction = rl.action
			bestExit = rl.exit
			bestTier = rl.tier
			bestBits = ruleBits
			bestGroupPriority = rl.groupPriority
			bestPriority = rl.priority
		}
	}
	return bestAction, bestExit
}
