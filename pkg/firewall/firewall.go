package firewall

import (
	"fmt"
	"liberator-node-go/internal/utils/dgmessage"
	"sync"
	"time"
)

// Protocol - tcp/udp/both
type PortRule struct {
	ID             uint64
	Address        uint32
	TargetAddress  *uint32
	Protocol       string // tcp/udp/both-
	PortRangeStart uint16
	PortRangeEnd   *uint16
}

type FirewallEngine interface {
	RuleCheck(hi dgmessage.HoleInfo) bool
	Holepunch(hi dgmessage.HoleInfo, dur time.Duration)

	RemoveRule(ruleID uint64) bool
	AddRule(PortRule) bool
}

type firewallEngineImpl struct {
	rulesByAddr map[uint32][]uint64
	rulesByID   map[uint64]PortRule
	rulesMu     sync.RWMutex

	holes sync.Map // map[string]time.Time | Активные дырки (stateful): ключ -> время истечения
}

func New() FirewallEngine {
	return &firewallEngineImpl{
		rulesByAddr: make(map[uint32][]uint64),
		rulesByID:   make(map[uint64]PortRule),
	}
}

func (fw *firewallEngineImpl) AddRule(rule PortRule) bool {
	if rule.ID == 0 {
		return false
	}

	fw.rulesMu.Lock()
	defer fw.rulesMu.Unlock()

	if _, ex := fw.rulesByID[rule.ID]; ex {
		return false
	}

	fw.rulesByID[rule.ID] = rule
	fw.rulesByAddr[rule.Address] = append(fw.rulesByAddr[rule.Address], rule.ID)
	return true
}

func (fw *firewallEngineImpl) RemoveRule(ruleID uint64) bool {
	fw.rulesMu.Lock()
	defer fw.rulesMu.Unlock()

	rule, ok := fw.rulesByID[ruleID]
	if !ok {
		return false
	}

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

	return true
}

// RuleCheck проверяет, разрешён ли пакет на основе правил и активных дырок.
// Если есть активная дырка для этого потока – возвращает true без проверки правил.
// Иначе проверяет правила пользователя-отправителя.
// holeInfo должен содержать SrcIP, DstIP, SrcPort, DstPort (как net.IP) и Protocol (string).
func (r *firewallEngineImpl) RuleCheck(holeInfo dgmessage.HoleInfo) bool {
	// 1. Проверяем активную дырку (stateful)
	flowKey := makeFlowKey(holeInfo.SrcIP, holeInfo.DstIP, holeInfo.SrcPort, holeInfo.DstPort, holeInfo.Protocol)
	if val, ok := r.holes.Load(flowKey); ok {
		if expire, ok := val.(time.Time); ok && time.Now().Before(expire) {
			return true
		} else {
			r.holes.Delete(flowKey)
		}
	}

	r.rulesMu.RLock()
	defer r.rulesMu.RUnlock()

	// 2. Находим получателя
	rulesIds, ex := r.rulesByAddr[holeInfo.DstIP]
	if !ex {
		return false
	}

	// 4. Для ICMP – проверяем только TargetUser
	if holeInfo.Protocol == "icmp" {
		for _, ruleId := range rulesIds {
			rule := r.rulesByID[ruleId]
			if rule.TargetAddress == nil || *rule.TargetAddress == holeInfo.SrcIP {
				return true
			}
		}
		return false
	}

	// 5. Для TCP/UDP – проверяем порты
	dstPort := holeInfo.DstPort

	for _, ruleId := range rulesIds {
		rule := r.rulesByID[ruleId]
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
func (r *firewallEngineImpl) Holepunch(holeInfo dgmessage.HoleInfo, duration time.Duration) {
	flowKey := makeFlowKey(holeInfo.SrcIP, holeInfo.DstIP, holeInfo.SrcPort, holeInfo.DstPort, holeInfo.Protocol)
	expire := time.Now().Add(duration)
	r.holes.Store(flowKey, expire)
}

// Вспомогательная функция для создания канонического ключа (упорядочиваем IP и порты)
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
