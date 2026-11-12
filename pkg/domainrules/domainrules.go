// Package domainrules хранит доменные правила по клиентам.
// Резолв домена в IP выполняет DNS-прокси; здесь только action/exit.
package domainrules

import (
	"strings"
	"sync"
)

type Rule struct {
	Domain        string
	Action        string
	Exit          string
	Tier          int
	GroupPriority int32
	Priority      int32
}

type Entry struct {
	ClientIP      uint32
	Domain        string
	Action        string
	Exit          string
	Tier          int
	GroupPriority int32
	Priority      int32
}

type Table struct {
	mu sync.RWMutex
	m  map[uint32]map[string]Rule
}

func New() *Table {
	return &Table{m: make(map[uint32]map[string]Rule)}
}

func normalizeDomain(d string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
}

func (t *Table) ReplaceAll(entries []Entry) {
	next := make(map[uint32]map[string]Rule, len(entries)/4+1)
	for _, e := range entries {
		d := normalizeDomain(e.Domain)
		if e.ClientIP == 0 || d == "" {
			continue
		}
		if e.Action == "" {
			e.Action = "exit"
		}
		m := next[e.ClientIP]
		if m == nil {
			m = make(map[string]Rule)
			next[e.ClientIP] = m
		}
		rule := Rule{
			Domain: d, Action: e.Action, Exit: e.Exit,
			Tier: e.Tier, GroupPriority: e.GroupPriority, Priority: e.Priority,
		}
		if old, ok := m[d]; ok && !better(rule, old) {
			continue
		}
		m[d] = rule
	}
	t.mu.Lock()
	t.m = next
	t.mu.Unlock()
}

func better(a, b Rule) bool {
	if a.Tier != b.Tier {
		return a.Tier < b.Tier
	}
	if a.GroupPriority != b.GroupPriority {
		return a.GroupPriority < b.GroupPriority
	}
	return a.Priority < b.Priority
}

func (t *Table) Lookup(clientIP uint32, domain string) (Rule, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	m := t.m[clientIP]
	if m == nil {
		return Rule{}, false
	}
	r, ok := m[normalizeDomain(domain)]
	return r, ok
}
