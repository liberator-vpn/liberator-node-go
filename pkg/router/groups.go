package router

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Общие групповые политики.
//
// Групповые правила передаются ноде один раз на группу, а не размножаются
// по каждому пользователю. Клиент хранит только список group_id, поэтому
// 40–50k правил в default-группе занимают память один раз, а не N раз.
//
// Поиск: двоичный trie по префиксам (32 шага) + map по доменам.

type GroupRuleInput struct {
	Prefix   string
	Domain   string
	Action   string
	Exit     string
	Priority int32
}

type GroupInput struct {
	ID       string
	Priority int32
	Rules    []GroupRuleInput
}

type ClientGroupsInput struct {
	ClientIP uint32
	GroupIDs []string
}

type groupRule struct {
	action        string
	exit          string
	priority      int32
	groupPriority int32
}

type trieNode struct {
	child [2]*trieNode
	rule  *groupRule
}

type prefixTrie struct {
	root *trieNode
}

func newPrefixTrie() *prefixTrie { return &prefixTrie{root: &trieNode{}} }

func addrToUint32(a netip.Addr) (uint32, bool) {
	if !a.Is4() {
		return 0, false
	}
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), true
}

func (t *prefixTrie) insert(prefix netip.Prefix, rule groupRule) {
	addr, ok := addrToUint32(prefix.Addr())
	if !ok {
		return
	}
	n := t.root
	for i := 31; i >= 32-prefix.Bits(); i-- {
		b := (addr >> uint(i)) & 1
		if n.child[b] == nil {
			n.child[b] = &trieNode{}
		}
		n = n.child[b]
	}
	r := rule
	n.rule = &r
}

// lookup возвращает самое специфичное правило для dst и длину его префикса.
func (t *prefixTrie) lookup(dst uint32) (groupRule, int, bool) {
	n := t.root
	var best *groupRule
	bestBits := -1
	if n.rule != nil {
		best = n.rule
		bestBits = 0
	}
	for i := 31; i >= 0; i-- {
		b := (dst >> uint(i)) & 1
		n = n.child[b]
		if n == nil {
			break
		}
		if n.rule != nil {
			best = n.rule
			bestBits = 32 - i
		}
	}
	if best == nil {
		return groupRule{}, 0, false
	}
	return *best, bestBits, true
}

type groupPolicy struct {
	id       string
	priority int32
	prefixes *prefixTrie
	domains  map[string]groupRule
}

type groupLookup struct {
	ipRule groupRule
	ipBits int
	ipOK   bool

	domRule groupRule
	domBits int
	domOK   bool

	deny bool
}

// ReplaceGroupRules атомарно заменяет набор общих групповых правил.
func (r *Router) ReplaceGroupRules(inputs []GroupInput) {
	next := make(map[string]*groupPolicy, len(inputs))
	for _, in := range inputs {
		gp := &groupPolicy{
			id:       in.ID,
			priority: in.Priority,
			prefixes: newPrefixTrie(),
			domains:  make(map[string]groupRule, len(in.Rules)),
		}
		for _, ru := range in.Rules {
			rule := groupRule{
				action: ru.Action, exit: ru.Exit,
				priority: ru.Priority, groupPriority: in.Priority,
			}
			if ru.Domain != "" {
				gp.domains[normalizeRuleDomain(ru.Domain)] = rule
				continue
			}
			if ru.Prefix == "" {
				continue
			}
			p, err := netip.ParsePrefix(ru.Prefix)
			if err != nil {
				continue
			}
			gp.prefixes.insert(p.Masked(), rule)
		}
		next[in.ID] = gp
	}

	hasDomains := false
	hasRules := false
	for _, in := range inputs {
		if len(in.Rules) > 0 {
			hasRules = true
		}
		for _, ru := range in.Rules {
			if ru.Domain != "" {
				hasDomains = true
				break
			}
		}
	}
	r.hasGroupDomains.Store(hasDomains)
	r.hasGroupRules.Store(hasRules)
	r.hasDomainRules.Store(r.hasDomainRules.Load() || hasDomains)
	r.refreshHasAnyRules()

	r.groupsMu.Lock()
	r.groupsByID = next
	r.rebuildClientGroupsLocked()
	r.groupsMu.Unlock()
	r.invalidatePinsIfChanged(groupRulesFingerprint(inputs), &r.groupFPReady, &r.groupRulesFP)
}

// ReplaceClientGroups задаёт, в каких группах состоит каждый клиент.
func (r *Router) ReplaceClientGroups(inputs []ClientGroupsInput) {
	ids := make(map[uint32][]string, len(inputs))
	for _, in := range inputs {
		ids[in.ClientIP] = in.GroupIDs
	}
	r.groupsMu.Lock()
	r.clientGroupIDs = ids
	r.rebuildClientGroupsLocked()
	r.groupsMu.Unlock()
	r.invalidatePinsIfChanged(clientGroupsFingerprint(inputs), &r.clientGrpReady, &r.clientGrpFP)
}

func (r *Router) rebuildClientGroupsLocked() {
	resolved := make(map[uint32][]*groupPolicy, len(r.clientGroupIDs))
	for ip, ids := range r.clientGroupIDs {
		list := make([]*groupPolicy, 0, len(ids))
		seen := make(map[string]struct{}, len(ids))
		for _, id := range ids {
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			if gp := r.groupsByID[id]; gp != nil {
				list = append(list, gp)
			}
		}
		sort.SliceStable(list, func(i, j int) bool {
			if list[i].priority != list[j].priority {
				return list[i].priority < list[j].priority
			}
			return list[i].id < list[j].id
		})
		resolved[ip] = list
	}
	r.clientGroups = resolved
}

// lookupGroups ищет лучшее групповое правило для клиента: по IP (trie) и по
// доменам, которые клиент резолвил в этот IP. globalDomains — все домены
// этого IP (для deny), clientDomains — домены конкретного клиента.
func (r *Router) lookupGroups(src, dst uint32, clientDomains, globalDomains []string) groupLookup {
	r.groupsMu.RLock()
	groups := r.clientGroups[src]
	r.groupsMu.RUnlock()
	var out groupLookup
	for _, gp := range groups {
		if rule, bits, ok := gp.prefixes.lookup(dst); ok {
			if !out.ipOK || betterGroupRule(rule, bits, out.ipRule, out.ipBits) {
				out.ipRule, out.ipBits, out.ipOK = rule, bits, true
			}
		}
		for _, d := range clientDomains {
			if rule, ok := gp.domains[d]; ok {
				if !out.domOK || betterGroupRule(rule, 32, out.domRule, out.domBits) {
					out.domRule, out.domBits, out.domOK = rule, 32, true
				}
			}
		}
		for _, d := range globalDomains {
			if rule, ok := gp.domains[d]; ok && rule.action == "deny" {
				out.deny = true
			}
		}
	}
	return out
}

// betterGroupRule: сначала специфичность, затем приоритет группы, затем
// приоритет правила (те же правила, что и в API mergeCandidates).
func betterGroupRule(a groupRule, aBits int, b groupRule, bBits int) bool {
	if aBits != bBits {
		return aBits > bBits
	}
	if a.groupPriority != b.groupPriority {
		return a.groupPriority < b.groupPriority
	}
	return a.priority < b.priority
}

func groupRulesFingerprint(inputs []GroupInput) uint64 {
	lines := make([]string, 0, len(inputs))
	for _, in := range inputs {
		for _, ru := range in.Rules {
			lines = append(lines, fmt.Sprintf("%s|%d|%s|%s|%s|%s|%d",
				in.ID, in.Priority, ru.Prefix, ru.Domain, ru.Action, ru.Exit, ru.Priority))
		}
	}
	return hashLines(lines)
}

func clientGroupsFingerprint(inputs []ClientGroupsInput) uint64 {
	lines := make([]string, 0, len(inputs))
	for _, in := range inputs {
		ids := append([]string(nil), in.GroupIDs...)
		sort.Strings(ids)
		lines = append(lines, fmt.Sprintf("%d|%s", in.ClientIP, strings.Join(ids, ",")))
	}
	return hashLines(lines)
}

func normalizeRuleDomain(d string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
}
