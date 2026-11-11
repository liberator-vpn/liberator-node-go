package xray

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"

	"github.com/vishvananda/netlink"
)

// policyManager решает две задачи:
//
//  1. Даёт каждому proxy-пользователю локальный source-IP (local_ip) и
//     назначает его /32 на dummy-интерфейс. Xray биндится на него через
//     sendThrough.
//  2. Через ip rule/ip route отправляет пакеты с local_ip в proxy-TUN.
//
// virtual_ip при этом НЕ назначается на хост. Нода переписывает source
// local_ip -> virtual_ip на входе из proxy-TUN и dst virtual_ip -> local_ip
// на выходе. Так весь трафик проходит через роутер ноды (учёт, шейпер,
// policy-egress), а не доставляется локальному сокету в обход.
type policyManager struct {
	mu sync.Mutex

	tunName   string
	dummyName string
	tunIndex  int
	dummy     netlink.Link

	baseTable    int
	basePriority int
	maxSlots     int

	baseLocal uint32
	localSize uint64
	nextLocal uint64

	byVIP    map[uint32]uint32 // virtual_ip -> local_ip
	byLocal  map[uint32]uint32 // local_ip -> virtual_ip
	vipSlots map[uint32]int    // virtual_ip -> policy slot
	used     map[int]uint32    // slot -> virtual_ip
}

const policySlots = 4096

func newPolicyManager(tunName, dummyName, localCIDR string, baseTable, basePriority int) (*policyManager, error) {
	tunLink, err := netlink.LinkByName(tunName)
	if err != nil {
		return nil, fmt.Errorf("xray: proxy tun %s not found: %w", tunName, err)
	}

	_, ipNet, err := net.ParseCIDR(localCIDR)
	if err != nil {
		return nil, fmt.Errorf("xray: invalid local_cidr %q: %w", localCIDR, err)
	}
	ones, bits := ipNet.Mask.Size()
	if bits != 32 || ones >= 32 {
		return nil, fmt.Errorf("xray: local_cidr must be an IPv4 subnet")
	}
	base := ipToUint32(ipNet.IP)
	size := uint64(1) << uint(32-ones)

	// Dummy пересоздаём с нуля: после падения процесса на нём могли остаться
	// старые /32 адреса.
	if err := deleteLinkAndWait(dummyName); err != nil {
		return nil, fmt.Errorf("xray: remove stale dummy %s: %w", dummyName, err)
	}
	dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: dummyName}}
	if err := netlink.LinkAdd(dummy); err != nil {
		return nil, fmt.Errorf("xray: create dummy %s: %w", dummyName, err)
	}
	if err := netlink.LinkSetUp(dummy); err != nil {
		_ = netlink.LinkDel(dummy)
		return nil, fmt.Errorf("xray: up dummy %s: %w", dummyName, err)
	}

	p := &policyManager{
		tunName:      tunName,
		dummyName:    dummyName,
		tunIndex:     tunLink.Attrs().Index,
		dummy:        dummy,
		baseTable:    baseTable,
		basePriority: basePriority,
		maxSlots:     policySlots,
		baseLocal:    base,
		localSize:    size,
		nextLocal:    0,
		byVIP:        make(map[uint32]uint32),
		byLocal:      make(map[uint32]uint32),
		vipSlots:     make(map[uint32]int),
		used:         make(map[int]uint32),
	}
	p.cleanupStaleRules()
	return p, nil
}

func (p *policyManager) cleanupStaleRules() {
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return
	}
	for i := range rules {
		r := rules[i]
		if r.Src == nil {
			continue
		}
		if r.Priority < p.basePriority || r.Priority >= p.basePriority+p.maxSlots {
			continue
		}
		if r.Table < p.baseTable || r.Table >= p.baseTable+p.maxSlots {
			continue
		}
		_ = netlink.RuleDel(&r)
	}
}

// addVIP резервирует local_ip для virtual_ip и настраивает policy routing.
func (p *policyManager) addVIP(vip net.IP) (net.IP, error) {
	v4 := vip.To4()
	if v4 == nil {
		return nil, fmt.Errorf("xray: virtual_ip %s is not IPv4", vip)
	}
	vipKey := ipToUint32(v4)

	p.mu.Lock()
	defer p.mu.Unlock()

	if local, ok := p.byVIP[vipKey]; ok {
		return uint32ToIP(local), nil
	}

	slot := p.pickSlotLocked()
	if slot == 0 {
		return nil, fmt.Errorf("xray: no free policy slots")
	}
	localKey, err := p.allocLocalLocked()
	if err != nil {
		return nil, err
	}
	localIP := uint32ToIP(localKey)
	localNet := &net.IPNet{IP: localIP, Mask: net.CIDRMask(32, 32)}
	table := p.baseTable + slot
	priority := p.basePriority + slot

	addr := &netlink.Addr{IPNet: localNet}
	if err := netlink.AddrAdd(p.dummy, addr); err != nil && !isExist(err) {
		return nil, fmt.Errorf("xray: add dummy address %s: %w", localIP, err)
	}

	rule := netlink.NewRule()
	rule.Family = netlink.FAMILY_V4
	rule.Src = localNet
	rule.Table = table
	rule.Priority = priority
	_ = netlink.RuleDel(rule)
	if err := netlink.RuleAdd(rule); err != nil {
		_ = netlink.AddrDel(p.dummy, addr)
		return nil, fmt.Errorf("xray: add ip rule for %s: %w", localIP, err)
	}

	route := defaultRoute(p.tunIndex, table)
	if err := netlink.RouteReplace(route); err != nil {
		_ = netlink.RuleDel(rule)
		_ = netlink.AddrDel(p.dummy, addr)
		return nil, fmt.Errorf("xray: add route for %s: %w", localIP, err)
	}

	p.byVIP[vipKey] = localKey
	p.byLocal[localKey] = vipKey
	p.vipSlots[vipKey] = slot
	p.used[slot] = vipKey
	return localIP, nil
}

func (p *policyManager) removeVIP(vip net.IP) {
	v4 := vip.To4()
	if v4 == nil {
		return
	}
	vipKey := ipToUint32(v4)

	p.mu.Lock()
	defer p.mu.Unlock()

	localKey, ok := p.byVIP[vipKey]
	if !ok {
		return
	}
	slot := p.vipSlots[vipKey]
	table := p.baseTable + slot
	priority := p.basePriority + slot
	localIP := uint32ToIP(localKey)
	localNet := &net.IPNet{IP: localIP, Mask: net.CIDRMask(32, 32)}

	_ = netlink.RouteDel(defaultRoute(p.tunIndex, table))
	rule := netlink.NewRule()
	rule.Family = netlink.FAMILY_V4
	rule.Src = localNet
	rule.Table = table
	rule.Priority = priority
	_ = netlink.RuleDel(rule)
	_ = netlink.AddrDel(p.dummy, &netlink.Addr{IPNet: localNet})

	delete(p.byVIP, vipKey)
	delete(p.byLocal, localKey)
	delete(p.vipSlots, vipKey)
	delete(p.used, slot)
}

func (p *policyManager) localForVIP(vip uint32) (net.IP, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	local, ok := p.byVIP[vip]
	if !ok {
		return nil, false
	}
	return uint32ToIP(local), true
}

func (p *policyManager) vipForLocal(local uint32) (uint32, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	vip, ok := p.byLocal[local]
	return vip, ok
}

func (p *policyManager) close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for vipKey, localKey := range p.byVIP {
		slot := p.vipSlots[vipKey]
		table := p.baseTable + slot
		priority := p.basePriority + slot
		localNet := &net.IPNet{IP: uint32ToIP(localKey), Mask: net.CIDRMask(32, 32)}
		_ = netlink.RouteDel(defaultRoute(p.tunIndex, table))
		rule := netlink.NewRule()
		rule.Family = netlink.FAMILY_V4
		rule.Src = localNet
		rule.Table = table
		rule.Priority = priority
		_ = netlink.RuleDel(rule)
		_ = netlink.AddrDel(p.dummy, &netlink.Addr{IPNet: localNet})
	}
	clear(p.byVIP)
	clear(p.byLocal)
	clear(p.vipSlots)
	clear(p.used)
	if p.dummy != nil {
		_ = netlink.LinkDel(p.dummy)
	}
}

func (p *policyManager) pickSlotLocked() int {
	for i := 1; i < p.maxSlots; i++ {
		if _, used := p.used[i]; !used {
			return i
		}
	}
	return 0
}

func (p *policyManager) allocLocalLocked() (uint32, error) {
	if p.localSize <= 2 {
		return 0, fmt.Errorf("xray: local_cidr is too small")
	}
	for tries := uint64(0); tries < p.localSize-1; tries++ {
		p.nextLocal++
		if p.nextLocal >= p.localSize {
			p.nextLocal = 1
		}
		candidate := p.baseLocal + uint32(p.nextLocal)
		if _, used := p.byLocal[candidate]; used {
			continue
		}
		return candidate, nil
	}
	return 0, fmt.Errorf("xray: local_cidr pool exhausted")
}

func ipToUint32(ip net.IP) uint32 {
	v4 := ip.To4()
	return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
}

func uint32ToIP(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).To4()
}

func isExist(err error) bool {
	return err != nil && errors.Is(err, syscall.EEXIST)
}

func defaultRoute(linkIndex, table int) *netlink.Route {
	return &netlink.Route{
		Family:    netlink.FAMILY_V4,
		LinkIndex: linkIndex,
		Table:     table,
		Scope:     netlink.SCOPE_LINK,
		Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
	}
}
