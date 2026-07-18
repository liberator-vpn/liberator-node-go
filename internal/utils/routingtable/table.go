package routingtable

import (
	"fmt"
	"liberator-node-go/internal/utils/dgmessage"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

type RoutingTableRecordDump struct {
	UserID    string
	VirtualIP string
	NodeID    string

	Rules []PortRule
}

type RoutingObject interface {
	GetNodeID() string
	GetUserID() uuid.UUID
	GetVirtualIP() net.IP
	SendDatagram([]byte) error
}

// Protocol - tcp/udp/both
type PortRule struct {
	User           uuid.UUID
	TargetUser     *uuid.UUID
	Protocol       string // tcp/udp/both
	PortRangeStart uint16
	PortRangeEnd   *uint16
}

type EventHandler = func(added, deleted RoutingObject)

type RoutingTable interface {
	Add(RoutingObject) error
	Delete(RoutingObject) error

	GetByUserID(uuid.UUID) (RoutingObject, bool)
	GetByVirtualIp(net.IP) (RoutingObject, bool)

	SendDatagram(net.IP, []byte) error

	RuleCheck(hi dgmessage.HoleInfo) bool
	Holepunch(hi dgmessage.HoleInfo, dur time.Duration)

	Dump() []RoutingTableRecordDump
	DumpRules(uuid.UUID) []PortRule

	AddRule(PortRule)

	AddEventHandler(EventHandler)
}

type routingTableImpl struct {
	byUserID    map[uuid.UUID]RoutingObject
	byVirtualIp map[string]RoutingObject
	updateLock  sync.RWMutex

	rules   map[uuid.UUID][]PortRule
	rulesMu sync.RWMutex

	holes sync.Map // map[string]time.Time | Активные дырки (stateful): ключ -> время истечения

	eventHandlers []EventHandler
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

	if ipEx && idEx {
		return nil
	}

	r.byUserID[obj.GetUserID()] = obj
	r.byVirtualIp[obj.GetVirtualIP().String()] = obj
	r.fireEvent(obj, nil)
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
	if !idEx && !ipEx {
		return nil
	}

	delete(r.byUserID, obj.GetUserID())
	delete(r.byVirtualIp, obj.GetVirtualIP().String())

	r.fireEvent(nil, obj)
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

func (r *routingTableImpl) SendDatagram(ip net.IP, data []byte) error {
	r.updateLock.RLock()
	defer r.updateLock.RUnlock()
	obj, ex := r.byVirtualIp[ip.String()]
	if !ex {
		return fmt.Errorf("not found")
	}
	return obj.SendDatagram(data)
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
func (r *routingTableImpl) RuleCheck(holeInfo dgmessage.HoleInfo) bool {
	// 1. Проверяем активную дырку (stateful)
	flowKey := makeFlowKey(holeInfo.SrcIP, holeInfo.DstIP, holeInfo.SrcPort, holeInfo.DstPort, holeInfo.Protocol)
	if val, ok := r.holes.Load(flowKey); ok {
		if expire, ok := val.(time.Time); ok && time.Now().Before(expire) {
			return true
		} else {
			r.holes.Delete(flowKey)
		}
	}

	// 2. Находим отправителя и получателя
	r.updateLock.RLock()
	srcObj, srcExists := r.byVirtualIp[holeInfo.SrcIP.String()]
	dstObj, dstExists := r.byVirtualIp[holeInfo.DstIP.String()]
	r.updateLock.RUnlock()
	if !srcExists || !dstExists {
		return false
	}
	srcUserID := srcObj.GetUserID()
	dstUserID := dstObj.GetUserID()

	// 3. Получаем правила ПОЛУЧАТЕЛЯ (dstUserID), а не отправителя
	r.rulesMu.RLock()
	rules, ok := r.rules[dstUserID] // <-- ИСПРАВЛЕНО
	r.rulesMu.RUnlock()
	if !ok || len(rules) == 0 {
		return false // если у получателя нет правил – запрещено
	}

	// 4. Для ICMP – проверяем только TargetUser
	if holeInfo.Protocol == "icmp" {
		for _, rule := range rules {
			if rule.TargetUser == nil || *rule.TargetUser == srcUserID {
				return true
			}
		}
		return false
	}

	// 5. Для TCP/UDP – проверяем порты
	dstPort := holeInfo.DstPort
	for _, rule := range rules {
		// Проверяем, что правило разрешает именно этому отправителю (srcUserID)
		if rule.TargetUser != nil && *rule.TargetUser != srcUserID {
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
func (r *routingTableImpl) Holepunch(holeInfo dgmessage.HoleInfo, duration time.Duration) {
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

func (r *routingTableImpl) DumpRules(userID uuid.UUID) []PortRule {
	r.rulesMu.RLock()
	rules := make([]PortRule, 0)
	for _, rule := range r.rules[userID] {
		rules = append(rules, rule)
	}
	r.rulesMu.RUnlock()
	return rules
}
func (r *routingTableImpl) Dump() []RoutingTableRecordDump {
	r.updateLock.Lock()
	defer r.updateLock.Unlock()
	dump := make([]RoutingTableRecordDump, 0, len(r.byUserID))
	for _, v := range r.byUserID {
		record := RoutingTableRecordDump{
			UserID:    v.GetUserID().String(),
			VirtualIP: v.GetVirtualIP().String(),
			NodeID:    v.GetNodeID(),
		}
		// Add rules
		record.Rules = r.DumpRules(v.GetUserID())

		dump = append(dump, record)
	}
	return dump
}

func (r *routingTableImpl) fireEvent(added, deleted RoutingObject) {
	for _, h := range r.eventHandlers {
		if h != nil {
			go h(added, deleted)
		}
	}
}
func (r *routingTableImpl) AddEventHandler(h EventHandler) {
	r.eventHandlers = append(r.eventHandlers, h)
}
