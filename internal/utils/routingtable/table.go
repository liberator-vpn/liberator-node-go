package routingtable

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

type RoutingObject interface {
	GetUserID() uuid.UUID
	GetVirtualIP() net.IP
	SendDatagram(data []byte) error
}

// Protocol - tcp/udp/both
type PortRule struct {
	User           uuid.UUID
	TargetUser     *uuid.UUID
	Protocol       string // tcp/udp/both
	PortRangeStart uint16
	PortRangeEnd   *uint16
}

type HoleInfo struct {
	SrcIP net.IP
	DstIP net.IP

	SrcPort uint16
	DstPort uint16

	Protocol string // tcp/udp/icmp
}

type RoutingTable interface {
	Add(RoutingObject) error
	Delete(RoutingObject) error

	GetByUserID(uuid.UUID) (RoutingObject, bool)
	GetByVirtualIp(net.IP) (RoutingObject, bool)

	RuleCheck(hi HoleInfo) bool
	Holepunch(hi HoleInfo, dur time.Duration)

	AddRule(PortRule)
}

type routingTableImpl struct {
	byUserID    map[uuid.UUID]RoutingObject
	byVirtualIp map[string]RoutingObject
	updateLock  sync.RWMutex

	rules   map[uuid.UUID][]PortRule
	rulesMu sync.RWMutex // можно использовать общий updateLock, но лучше отдельный

	// Активные дырки (stateful): ключ -> время истечения
	holes sync.Map // map[string]time.Time
}

func New() RoutingTable {
	return &routingTableImpl{
		byUserID:    map[uuid.UUID]RoutingObject{},
		byVirtualIp: map[string]RoutingObject{},
		rules:       make(map[uuid.UUID][]PortRule),
	}
}

// Add implements [RoutingTable].
func (r *routingTableImpl) Add(obj RoutingObject) error {
	r.updateLock.Lock()
	defer r.updateLock.Unlock()

	// Check if partially exist
	_, idEx := r.byUserID[obj.GetUserID()]
	_, ipEx := r.byVirtualIp[obj.GetVirtualIP().String()]
	if idEx != ipEx {
		return fmt.Errorf("failed to add partially existing routing object")
	}

	r.byUserID[obj.GetUserID()] = obj
	r.byVirtualIp[obj.GetVirtualIP().String()] = obj
	return nil
}

// Delete implements [RoutingTable].
func (r *routingTableImpl) Delete(obj RoutingObject) error {
	r.updateLock.Lock()
	defer r.updateLock.Unlock()

	// Check if partially exist
	_, idEx := r.byUserID[obj.GetUserID()]
	_, ipEx := r.byVirtualIp[obj.GetVirtualIP().String()]
	if idEx != ipEx {
		return fmt.Errorf("failed to add partially existing routing object")
	}

	delete(r.byUserID, obj.GetUserID())
	delete(r.byVirtualIp, obj.GetVirtualIP().String())

	return nil
}

// GetByUserID implements [RoutingTable].
func (r *routingTableImpl) GetByUserID(id uuid.UUID) (RoutingObject, bool) {
	r.updateLock.RLock()
	defer r.updateLock.RUnlock()
	obj, ex := r.byUserID[id]
	return obj, ex
}

// GetByVirtualIp implements [RoutingTable].
func (r *routingTableImpl) GetByVirtualIp(ip net.IP) (RoutingObject, bool) {
	r.updateLock.RLock()
	defer r.updateLock.RUnlock()
	obj, ex := r.byVirtualIp[ip.String()]
	return obj, ex
}

// INTERCONNECTIONS

// Добавление правила (вызывается извне при изменении политик)
func (r *routingTableImpl) AddRule(rule PortRule) {
	r.rulesMu.Lock()
	defer r.rulesMu.Unlock()
	r.rules[rule.User] = append(r.rules[rule.User], rule)

	// Оптимизируем правила для этого пользователя
	r.optimizeRulesForUser(rule.User)
}

// RuleCheck проверяет, разрешён ли пакет на основе правил и активных дырок.
// Если есть активная дырка для этого потока – возвращает true без проверки правил.
// Иначе проверяет правила пользователя-отправителя.
// holeInfo должен содержать SrcIP, DstIP, SrcPort, DstPort (как net.IP) и Protocol (string).
func (r *routingTableImpl) RuleCheck(holeInfo HoleInfo) bool {
	// 1. Проверяем активную дырку
	flowKey := makeFlowKey(holeInfo.SrcIP, holeInfo.DstIP, holeInfo.SrcPort, holeInfo.DstPort, holeInfo.Protocol)
	if val, ok := r.holes.Load(flowKey); ok {
		if expire, ok := val.(time.Time); ok && time.Now().Before(expire) {
			return true // дырка активна
		} else {
			r.holes.Delete(flowKey) // истекла – удаляем
		}
	}

	// 2. Находим отправителя и получателя по IP
	r.updateLock.RLock()
	srcObj, srcExists := r.byVirtualIp[holeInfo.SrcIP.String()]
	dstObj, dstExists := r.byVirtualIp[holeInfo.DstIP.String()]
	r.updateLock.RUnlock()
	if !srcExists || !dstExists {
		return false // один из участников не найден
	}
	srcUserID := srcObj.GetUserID()
	dstUserID := dstObj.GetUserID()

	// 3. Получаем правила отправителя
	r.rulesMu.RLock()
	rules, ok := r.rules[srcUserID]
	r.rulesMu.RUnlock()
	if !ok || len(rules) == 0 {
		// Нет правил – запрещаем (можно изменить на true, если нужна политика "всё разрешено")
		return false
	}

	// 4. Отдельная ветка для ICMP – проверяем только наличие правила по TargetUser
	if holeInfo.Protocol == "icmp" {
		for _, rule := range rules {
			if rule.TargetUser == nil || *rule.TargetUser == dstUserID {
				return true
			}
		}
		return false
	}

	// 5. Для TCP/UDP – проверяем порты
	dstPort := holeInfo.DstPort // уже uint16
	for _, rule := range rules {
		// Проверяем получателя
		if rule.TargetUser != nil && *rule.TargetUser != dstUserID {
			continue
		}
		// Проверяем протокол
		if rule.Protocol != "both" && rule.Protocol != holeInfo.Protocol {
			continue
		}
		// Проверяем порт (точное совпадение или диапазон)
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
func (r *routingTableImpl) Holepunch(holeInfo HoleInfo, duration time.Duration) {
	flowKey := makeFlowKey(holeInfo.SrcIP, holeInfo.DstIP, holeInfo.SrcPort, holeInfo.DstPort, holeInfo.Protocol)
	expire := time.Now().Add(duration)
	r.holes.Store(flowKey, expire)
}

// Вспомогательная функция для создания канонического ключа (упорядочиваем IP и порты)
func makeFlowKey(srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol string) string {
	srcIPStr := srcIP.String()
	dstIPStr := dstIP.String()

	// Для ICMP порты не учитываем
	if protocol == "icmp" {
		if srcIPStr < dstIPStr {
			return fmt.Sprintf("%s|%s|icmp", srcIPStr, dstIPStr)
		} else {
			return fmt.Sprintf("%s|%s|icmp", dstIPStr, srcIPStr)
		}
	}
	// Для TCP/UDP – упорядочиваем пары (IP, порт)
	if srcIPStr < dstIPStr || (srcIPStr == dstIPStr && srcPort < dstPort) {
		return fmt.Sprintf("%s|%s|%d|%d|%s", srcIPStr, dstIPStr, srcPort, dstPort, protocol)
	} else {
		return fmt.Sprintf("%s|%s|%d|%d|%s", dstIPStr, srcIPStr, dstPort, srcPort, protocol)
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
func (r *routingTableImpl) optimizeRulesForUser(userID uuid.UUID) {
	rules := r.rules[userID]
	if len(rules) == 0 {
		return
	}

	// Группируем по (TargetUser, Protocol)
	groups := make(map[string][]PortRule)
	for _, rule := range rules {
		targetKey := "nil"
		if rule.TargetUser != nil {
			targetKey = rule.TargetUser.String()
		}
		key := targetKey + "|" + rule.Protocol
		groups[key] = append(groups[key], rule)
	}

	newRules := make([]PortRule, 0, len(rules))
	for _, groupRules := range groups {
		merged := mergeIntervals(groupRules)
		newRules = append(newRules, merged...)
	}

	// (Опционально) удаляем правила, покрываемые правилами для всех (targetUser=nil)
	// можно добавить отдельную функцию, если нужно

	r.rules[userID] = newRules
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
			User:           sample.User,
			TargetUser:     sample.TargetUser,
			Protocol:       sample.Protocol,
			PortRangeStart: in.start,
			PortRangeEnd:   endPtr,
		})
	}
	return result
}
