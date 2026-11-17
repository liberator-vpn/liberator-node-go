package firewall

import (
	"sync"
	"time"

	"github.com/liberator-vpn/liberator-node-go/internal/utils/dgmessage"
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

// ruleKey — полный ключ правила. Раньше он упаковывался в uint64
// (16 бит short node id + 48 бит локального RuleID), из-за чего RuleID
// усекался, а пары (recipient, sender) с разными старшими битами IP
// коллизировали. Держим ключ структурой — без потерь и без выгорания
// 16-битного пространства node id.
type ruleKey struct {
	nodeID string
	ruleID uint64
}

type firewallEngineImpl struct {
	rulesByAddr map[uint32][]ruleKey
	rulesByID   map[ruleKey]PortRule
	rulesMu     sync.RWMutex

	holes sync.Map // map[flowKey]hole | Активные дырки (stateful)
}

// flowKey — comparable-ключ потока. Раньше он собирался через fmt.Sprintf
// в string: на каждый пакет приходились Sprintf и две аллокации. Структура
// не аллоцирует и быстрее хэшируется.
type flowKey struct {
	srcIP   uint32
	dstIP   uint32
	srcPort uint16
	dstPort uint16
	proto   uint8
}

func protocolID(p string) uint8 {
	switch p {
	case "tcp":
		return 6
	case "udp":
		return 17
	case "icmp":
		return 1
	default:
		return 0
	}
}

// hole — разрешенный поток. HoleInfo храним, чтобы дырку можно было перепроверить
// по правилам после того, как правило удалили.
type hole struct {
	expire time.Time
	info   dgmessage.HoleInfo
}

func New() FirewallEngine {
	return &firewallEngineImpl{
		rulesByAddr: make(map[uint32][]ruleKey),
		rulesByID:   make(map[ruleKey]PortRule),
	}
}

func (fw *firewallEngineImpl) AddRule(index PortRuleIndex, rule PortRule) bool {
	if len(index.NodeID) == 0 {
		return false
	}
	key := ruleKey{nodeID: index.NodeID, ruleID: index.RuleID}

	fw.rulesMu.Lock()
	defer fw.rulesMu.Unlock()

	if _, ex := fw.rulesByID[key]; ex {
		return false
	}

	rule.index = index
	fw.rulesByID[key] = rule
	fw.rulesByAddr[rule.Address] = append(fw.rulesByAddr[rule.Address], key)
	return true
}

func (fw *firewallEngineImpl) ExistsRule(index PortRuleIndex) bool {
	if len(index.NodeID) == 0 {
		return false
	}
	key := ruleKey{nodeID: index.NodeID, ruleID: index.RuleID}

	fw.rulesMu.RLock()
	defer fw.rulesMu.RUnlock()

	_, ex := fw.rulesByID[key]
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
	if len(index.NodeID) == 0 {
		return false
	}
	key := ruleKey{nodeID: index.NodeID, ruleID: index.RuleID}

	fw.rulesMu.Lock()
	rule, ok := fw.rulesByID[key]
	if ok {
		delete(fw.rulesByID, key)

		ids := fw.rulesByAddr[rule.Address]
		for i, id := range ids {
			if id == key {
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
	key := makeFlowKey(holeInfo.SrcIP, holeInfo.DstIP, holeInfo.SrcPort, holeInfo.DstPort, holeInfo.Protocol)
	if val, ok := fw.holes.Load(key); ok {
		if h, ok := val.(hole); ok && time.Now().Before(h.expire) {
			return true
		} else {
			fw.holes.Delete(key)
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
//
// На каждый пакет из mesh в сторону локального клиента Store делать нельзя:
// это аллокация hole + запись в sync.Map на 100% download-трафика. Продлеваем
// дырку только когда до истечения осталось меньше половины TTL.
func (fw *firewallEngineImpl) Holepunch(holeInfo dgmessage.HoleInfo, duration time.Duration) {
	key := makeFlowKey(holeInfo.SrcIP, holeInfo.DstIP, holeInfo.SrcPort, holeInfo.DstPort, holeInfo.Protocol)
	now := time.Now()
	if val, ok := fw.holes.Load(key); ok {
		if h, ok := val.(hole); ok && h.expire.Sub(now) > duration/2 {
			return
		}
	}
	fw.holes.Store(key, hole{
		expire: now.Add(duration),
		info:   holeInfo,
	})
}

// makeFlowKey строит канонический ключ потока (упорядочивает IP и порты).
func makeFlowKey(srcIP, dstIP uint32, srcPort, dstPort uint16, protocol string) flowKey {
	proto := protocolID(protocol)
	// Для ICMP порты не учитываем.
	if proto == 1 {
		if srcIP > dstIP {
			srcIP, dstIP = dstIP, srcIP
		}
		return flowKey{srcIP: srcIP, dstIP: dstIP, proto: proto}
	}
	// Для TCP/UDP – упорядочиваем пары (IP, порт).
	if srcIP > dstIP || (srcIP == dstIP && srcPort > dstPort) {
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, srcPort
	}
	return flowKey{srcIP: srcIP, dstIP: dstIP, srcPort: srcPort, dstPort: dstPort, proto: proto}
}
