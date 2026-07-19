package firewall

import (
	"fmt"
	"liberator-node-go/internal/utils/dgmessage"
	"net"
	"sort"
	"sync"
	"time"
)

// Protocol - tcp/udp/both
type PortRule struct {
	Address        uint32
	TargetAddress  *uint32
	Protocol       string // tcp/udp/both-
	PortRangeStart uint16
	PortRangeEnd   *uint16
}

type FirewallEngine interface {
	RuleCheck(hi dgmessage.HoleInfo) bool
	Holepunch(hi dgmessage.HoleInfo, dur time.Duration)

	AddRule(PortRule)
}

type firewallEngineImpl struct {
	rules   map[uint32][]PortRule // By outbound rules by virtual ip
	rulesMu sync.RWMutex

	holes sync.Map // map[string]time.Time | Активные дырки (stateful): ключ -> время истечения
}

func New() FirewallEngine {
	return &firewallEngineImpl{
		rules: make(map[uint32][]PortRule),
	}
}

// Добавление правила (вызывается извне при изменении политик)
func (r *firewallEngineImpl) AddRule(rule PortRule) {
	r.rulesMu.Lock()
	defer r.rulesMu.Unlock()
	r.rules[rule.Address] = append(r.rules[rule.Address], rule)

	// Оптимизируем правила для этого пользователя
	r.optimizeRulesForUser(rule.Address)
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

	// 2. Находим получателя
	dstRules, dstExists := r.rules[holeInfo.DstIP]

	if !dstExists {
		return false
	}

	// 3. Получаем правила ПОЛУЧАТЕЛЯ (dstUserID), а не отправителя
	if !dstExists || len(dstRules) == 0 {
		return false // если у получателя нет правил – запрещено
	}

	// 4. Для ICMP – проверяем только TargetUser
	if holeInfo.Protocol == "icmp" {
		for _, rule := range dstRules {
			if rule.TargetAddress == nil || *rule.TargetAddress == holeInfo.SrcIP {
				return true
			}
		}
		return false
	}

	// 5. Для TCP/UDP – проверяем порты
	dstPort := holeInfo.DstPort
	for _, rule := range dstRules {
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

// Преобразование net.IP в uint16 (порт)
func ipToPort(ip net.IP) uint16 {
	// Предполагаем, что ip содержит 4 байта, где первые два — порт в big-endian
	if len(ip) >= 2 {
		return uint16(ip[0])<<8 | uint16(ip[1])
	}
	return 0
}

// optimizeRulesForUser перестраивает правила пользователя, объединяя перекрывающиеся диапазоны.
func (r *firewallEngineImpl) optimizeRulesForUser(address uint32) {
	rules := r.rules[address]
	if len(rules) == 0 {
		return
	}

	// Группируем по (TargetUser, Protocol)
	groups := make(map[string][]PortRule)
	for _, rule := range rules {
		var targetKey uint32
		if rule.TargetAddress != nil {
			targetKey = *rule.TargetAddress
		}
		key := fmt.Sprintf("%d|%s", targetKey, rule.Protocol)
		groups[key] = append(groups[key], rule)
	}

	newRules := make([]PortRule, 0, len(rules))
	for _, groupRules := range groups {
		merged := mergeIntervals(groupRules)
		newRules = append(newRules, merged...)
	}

	r.rules[address] = newRules
}

func mergeIntervals(rules []PortRule) []PortRule {
	if len(rules) <= 1 {
		return rules
	}

	// Извлекаем интервалы
	type interval struct {
		start uint16
		end   uint16
	}
	intervals := make([]interval, len(rules))
	for i, rule := range rules {
		start := rule.PortRangeStart
		end := rule.PortRangeStart
		if rule.PortRangeEnd != nil {
			end = *rule.PortRangeEnd
		}
		intervals[i] = interval{start, end}
	}

	// Сортируем по началу
	sort.Slice(intervals, func(i, j int) bool {
		return intervals[i].start < intervals[j].start
	})

	// Сливаем пересекающиеся и смежные (смежные — чтобы объединить 1-10 и 11-20 в 1-20)
	merged := make([]interval, 0, len(intervals))
	cur := intervals[0]
	for _, next := range intervals[1:] {
		if next.start <= cur.end+1 {
			if next.end > cur.end {
				cur.end = next.end
			}
		} else {
			merged = append(merged, cur)
			cur = next
		}
	}
	merged = append(merged, cur)

	// Преобразуем обратно в PortRule, используя первый rule как образец
	result := make([]PortRule, 0, len(merged))
	sample := rules[0] // все правила в группе имеют одинаковые User, TargetUser, Protocol
	for _, in := range merged {
		var endPtr *uint16
		if in.end != in.start {
			endPtr = &in.end
		}
		result = append(result, PortRule{
			Address:        sample.Address,
			TargetAddress:  sample.TargetAddress,
			Protocol:       sample.Protocol,
			PortRangeStart: in.start,
			PortRangeEnd:   endPtr,
		})
	}
	return result
}
