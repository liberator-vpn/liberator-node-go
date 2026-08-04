package firewall

import (
	"fmt"
	"sync"
	"time"

	"github.com/TexHik620953/liberator-node-go/internal/utils/dgmessage"
)

type RuleDump struct {
	NodeID string
	RuleID uint64

	Address        uint32
	TargetAddress  *uint32
	Protocol       string
	PortRangeStart uint16
	PortRangeEnd   *uint16
}

type PortRuleIndex struct {
	NodeID string
	RuleID uint64
}

// Protocol - tcp/udp/both
type PortRule struct {
	index PortRuleIndex

	Address        uint32
	TargetAddress  *uint32
	Protocol       string // tcp/udp/both-
	PortRangeStart uint16
	PortRangeEnd   *uint16
}

type FirewallEngine interface {
	// Hot path
	RuleCheck(hi dgmessage.HoleInfo) bool
	Holepunch(hi dgmessage.HoleInfo, dur time.Duration)

	// Controll plane
	AddRule(index PortRuleIndex, rule PortRule) bool
	ExistsRule(index PortRuleIndex) bool
	RemoveRule(index PortRuleIndex) bool
	DumpRules() []RuleDump
}

type firewallEngineImpl struct {
	rulesByAddr map[uint32][]uint64
	rulesByID   map[uint64]PortRule
	rulesMu     sync.RWMutex

	shortIdByNodeId map[string]uint16
	nextShortID     uint16
	nodeIDMu        sync.Mutex

	holes sync.Map // map[string]hole | Активные дырки (stateful)
}

// hole — разрешенный поток. HoleInfo храним, чтобы дырку можно было перепроверить
// по правилам после того, как правило удалили.
type hole struct {
	expire time.Time
	info   dgmessage.HoleInfo
}

func New() FirewallEngine {
	return &firewallEngineImpl{
		rulesByAddr:     make(map[uint32][]uint64),
		rulesByID:       make(map[uint64]PortRule),
		shortIdByNodeId: make(map[string]uint16),
	}
}

func (fw *firewallEngineImpl) AddRule(index PortRuleIndex, rule PortRule) bool {
	if len(index.NodeID) == 0 {
		return false
	}
	shortNodeID := fw.getOrCreateShortID(index.NodeID)
	ruleID := makeGlobalKey(shortNodeID, index.RuleID)

	fw.rulesMu.Lock()
	defer fw.rulesMu.Unlock()

	if _, ex := fw.rulesByID[ruleID]; ex {
		return false
	}

	rule.index = index
	fw.rulesByID[ruleID] = rule
	fw.rulesByAddr[rule.Address] = append(fw.rulesByAddr[rule.Address], ruleID)
	return true
}

func (fw *firewallEngineImpl) ExistsRule(index PortRuleIndex) bool {
	shortNodeID, ex := fw.getShortID(index.NodeID)
	if !ex {
		return false
	}
	ruleID := makeGlobalKey(shortNodeID, index.RuleID)

	fw.rulesMu.Lock()
	defer fw.rulesMu.Unlock()

	_, ex = fw.rulesByID[ruleID]
	return ex
}

func (fw *firewallEngineImpl) DumpRules() []RuleDump {
	fw.rulesMu.RLock()
	defer fw.rulesMu.RUnlock()
	r := make([]RuleDump, 0, len(fw.rulesByID))
	for _, rule := range fw.rulesByID {
		dump := RuleDump{
			NodeID:         rule.index.NodeID,
			RuleID:         rule.index.RuleID,
			Address:        rule.Address,
			TargetAddress:  rule.TargetAddress,
			Protocol:       rule.Protocol,
			PortRangeStart: rule.PortRangeStart,
			PortRangeEnd:   rule.PortRangeEnd,
		}
		if rule.TargetAddress != nil {
			val := *rule.TargetAddress
			dump.TargetAddress = &val
		}
		if rule.PortRangeEnd != nil {
			val := *rule.PortRangeEnd
			dump.PortRangeEnd = &val
		}
		r = append(r, dump)
	}
	return r
}

func (fw *firewallEngineImpl) RemoveRule(index PortRuleIndex) bool {
	shortNodeID, ex := fw.getShortID(index.NodeID)
	if !ex {
		return false
	}
	ruleID := makeGlobalKey(shortNodeID, index.RuleID)

	fw.rulesMu.Lock()
	rule, ok := fw.rulesByID[ruleID]
	if ok {
		delete(fw.rulesByID, ruleID)

		ids := fw.rulesByAddr[rule.Address]
		for i, id := range ids {
			if id == ruleID {
				fw.rulesByAddr[rule.Address] = append(ids[:i], ids[i+1:]...)
				break
			}
		}
		if len(fw.rulesByAddr[rule.Address]) == 0 {
			delete(fw.rulesByAddr, rule.Address)
		}
	}
	fw.rulesMu.Unlock()

	if !ok {
		return false
	}

	fw.dropUnauthorizedHoles()
	return true
}

// dropUnauthorizedHoles выкидывает дырки, которые больше не разрешены ни одним правилом.
// Без этого удаление правила не останавливает уже идущий поток: дырка живет минуту и
// продлевается каждым пакетом в любую сторону, то есть держится вечно, пока трафик идет.
// ponytail: полный проход по дыркам, но удаление правила это редкая операция control plane.
func (fw *firewallEngineImpl) dropUnauthorizedHoles() {
	fw.holes.Range(func(key, val any) bool {
		h, ok := val.(hole)
		if !ok || !fw.rulesAllow(h.info) {
			fw.holes.Delete(key)
		}
		return true
	})
}

// RuleCheck проверяет, разрешён ли пакет на основе правил и активных дырок.
// Если есть активная дырка для этого потока – возвращает true без проверки правил.
// Иначе проверяет правила пользователя-отправителя.
// holeInfo должен содержать SrcIP, DstIP, SrcPort, DstPort (как net.IP) и Protocol (string).
func (fw *firewallEngineImpl) RuleCheck(holeInfo dgmessage.HoleInfo) bool {
	// 1. Проверяем активную дырку (stateful)
	flowKey := makeFlowKey(holeInfo.SrcIP, holeInfo.DstIP, holeInfo.SrcPort, holeInfo.DstPort, holeInfo.Protocol)
	if val, ok := fw.holes.Load(flowKey); ok {
		if h, ok := val.(hole); ok && time.Now().Before(h.expire) {
			return true
		} else {
			fw.holes.Delete(flowKey)
		}
	}

	return fw.rulesAllow(holeInfo)
}

// rulesAllow проверяет пакет только по правилам, без учета дырок.
func (fw *firewallEngineImpl) rulesAllow(holeInfo dgmessage.HoleInfo) bool {
	fw.rulesMu.RLock()
	defer fw.rulesMu.RUnlock()

	// 2. Находим получателя
	rulesIds, ex := fw.rulesByAddr[holeInfo.DstIP]
	if !ex {
		return false
	}

	// 4. Для ICMP – проверяем только TargetUser
	if holeInfo.Protocol == "icmp" {
		for _, ruleId := range rulesIds {
			rule := fw.rulesByID[ruleId]
			if rule.TargetAddress == nil || *rule.TargetAddress == holeInfo.SrcIP {
				return true
			}
		}
		return false
	}

	// 5. Для TCP/UDP – проверяем порты
	dstPort := holeInfo.DstPort

	for _, ruleId := range rulesIds {
		rule := fw.rulesByID[ruleId]
		// Проверяем, что правило разрешает именно этому отправителю (srcUserID)
		if rule.TargetAddress != nil && *rule.TargetAddress != holeInfo.SrcIP {
			continue
		}
		// Проверяем протокол
		if rule.Protocol != "both" && rule.Protocol != holeInfo.Protocol {
			continue
		}
		// Проверяем порт назначения (это порт получателя)
		if rule.PortRangeEnd == nil {
			if uint16(rule.PortRangeStart) == dstPort {
				return true
			}
		} else {
			if uint16(rule.PortRangeStart) <= dstPort && dstPort <= uint16(*rule.PortRangeEnd) {
				return true
			}
		}
	}
	return false
}

// Holepunch создаёт (или обновляет) дырку для данного потока на заданное время.
// Вызывается после успешной проверки правил для первого пакета.
func (fw *firewallEngineImpl) Holepunch(holeInfo dgmessage.HoleInfo, duration time.Duration) {
	flowKey := makeFlowKey(holeInfo.SrcIP, holeInfo.DstIP, holeInfo.SrcPort, holeInfo.DstPort, holeInfo.Protocol)
	fw.holes.Store(flowKey, hole{
		expire: time.Now().Add(duration),
		info:   holeInfo,
	})
}

// Вспомогательная функция для создания канонического ключа (упорядочиваем IP и порты)
// TODO: move this to fixed size struct key to avoid allocs
func makeFlowKey(srcIP, dstIP uint32, srcPort, dstPort uint16, protocol string) string {

	// Для ICMP порты не учитываем
	if protocol == "icmp" {
		if srcIP < dstIP {
			return fmt.Sprintf("%d|%d|icmp", srcIP, dstIP)
		} else {
			return fmt.Sprintf("%d|%d|icmp", dstIP, srcIP)
		}
	}

	// Для TCP/UDP – упорядочиваем пары (IP, порт)
	if srcIP < dstIP || (srcIP == dstIP && srcPort < dstPort) {
		return fmt.Sprintf("%d|%d|%d|%d|%s", srcIP, dstIP, srcPort, dstPort, protocol)
	} else {
		return fmt.Sprintf("%d|%d|%d|%d|%s", dstIP, srcIP, dstPort, srcPort, protocol)
	}
}

func (fw *firewallEngineImpl) getShortID(nodeHash string) (uint16, bool) {
	fw.nodeIDMu.Lock()
	defer fw.nodeIDMu.Unlock()

	id, exists := fw.shortIdByNodeId[nodeHash]
	return id, exists
}

func (fw *firewallEngineImpl) getOrCreateShortID(nodeHash string) uint16 {
	fw.nodeIDMu.Lock()
	defer fw.nodeIDMu.Unlock()

	if id, exists := fw.shortIdByNodeId[nodeHash]; exists {
		return id
	}

	// Регистрируем новую ноду, инкрементируя счетчик
	fw.nextShortID++
	fw.shortIdByNodeId[nodeHash] = fw.nextShortID
	return fw.nextShortID
}
func makeGlobalKey(shortID uint16, localRuleID uint64) uint64 {
	return (uint64(shortID) << 48) | (localRuleID & 0x0000FFFFFFFFFFFF)
}
