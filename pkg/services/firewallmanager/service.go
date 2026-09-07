package firewallmanager

import (
	"sync"

	"github.com/liberator-vpn/liberator-node-go/pkg/firewall"
	"github.com/liberator-vpn/liberator-node-go/pkg/model"
)

type Firewall interface {
	AddRule(index firewall.PortRuleIndex, rule firewall.PortRule) bool
	RemoveRule(index firewall.PortRuleIndex) bool
}

// Firewallmanager применяет правила файрвола в рантайме. Правила живут только в
// памяти (config-фид / будущий state из API), без персистентной БД.
type Firewallmanager struct {
	firewall Firewall
	nodeID   string

	mu        sync.Mutex
	nextID    uint64
	peerRules map[uint32][]uint64 // virtualIP -> правило ID
}

func New(firewall Firewall, nodeID string) *Firewallmanager {
	return &Firewallmanager{
		firewall:  firewall,
		nodeID:    nodeID,
		nextID:    1,
		peerRules: make(map[uint32][]uint64),
	}
}

// AddRule добавляет правило для клиента с virtualIP и возвращает его ID.
func (fm *Firewallmanager) AddRule(virtualIP uint32, rule model.PortRule) uint64 {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	id := fm.nextID
	fm.nextID++
	rule.ID = id

	ok := fm.firewall.AddRule(firewall.PortRuleIndex{
		NodeID: fm.nodeID,
		RuleID: id,
	}, firewall.PortRule{
		Address:        virtualIP,
		TargetAddress:  rule.TargetAddress,
		Protocol:       rule.Protocol,
		PortRangeStart: rule.PortRangeStart,
		PortRangeEnd:   rule.PortRangeEnd,
	})
	if !ok {
		return 0
	}
	fm.peerRules[virtualIP] = append(fm.peerRules[virtualIP], id)
	return id
}

// RemoveAllPeerRules снимает все правила клиента с virtualIP.
func (fm *Firewallmanager) RemoveAllPeerRules(virtualIP uint32) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	for _, id := range fm.peerRules[virtualIP] {
		fm.firewall.RemoveRule(firewall.PortRuleIndex{
			NodeID: fm.nodeID,
			RuleID: id,
		})
	}
	delete(fm.peerRules, virtualIP)
}
