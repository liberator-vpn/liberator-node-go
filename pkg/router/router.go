package router

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"runtime"
	"sync"
	"time"

	"github.com/liberator-vpn/liberator-node-go/internal/metrics"
	"github.com/liberator-vpn/liberator-node-go/internal/utils/dgmessage"
	"github.com/liberator-vpn/liberator-node-go/internal/utils/netutils"
	"github.com/liberator-vpn/liberator-node-go/pkg/dnsproxy"
	"github.com/liberator-vpn/liberator-node-go/pkg/domainrules"
	"github.com/liberator-vpn/liberator-node-go/pkg/firewall"
	"github.com/liberator-vpn/liberator-node-go/pkg/routingtable"
	"github.com/liberator-vpn/liberator-node-go/pkg/userrules"
)

type UDPDNSHandler interface {
	HandleUDPQuery(clientIP uint32, query []byte) []byte
}

type Router struct {
	ctx         context.Context
	packetsPool dgmessage.DGMessagePool

	routingTable routingtable.RoutingTable
	firewall     firewall.FirewallEngine

	toIface chan *dgmessage.DatagramMessage

	gatewayAddr   uint32
	globalNetwork netutils.NativeIPNet

	shardedWorkers []chan datagramMessageInfo

	routingsubs   map[chan RouterEvent]struct{}
	routingSubsMu sync.Mutex

	firewallsubs   map[chan FirewallEvent]struct{}
	firewallSubsMu sync.Mutex

	// Policy-egress: решение «в какую ноду-выход слать» принимает таблица
	// userRules (данные вне роутера, по аналогии с routingTable). exitFn —
	// примитив отправки сырого пакета ноде-выходу.
	exitMu    sync.RWMutex
	exitFn    func(endpoint string, data []byte) error
	userRules *userrules.UserRules

	domainRules *domainrules.Table
	domainCache *dnsproxy.Cache
	dnsHandler  UDPDNSHandler

	pinsMu sync.Mutex
	pins   map[uint64]pin
}

type pin struct {
	action  string
	exit    string
	expires time.Time
}

func New(
	ctx context.Context,
	gatewayAddrStr, globalCIDR string,
) (*Router, error) {
	if gatewayAddrStr == "" {
		return nil, fmt.Errorf("gateway_addr must be provided")
	}
	gatewayAddr := netutils.IPStringToUint32(gatewayAddrStr)
	if gatewayAddr == 0 {
		return nil, fmt.Errorf("invalid gateway_addr: %q", gatewayAddrStr)
	}

	_, globalNetwork, err := netutils.NewNativeIPNet(globalCIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid global CIDR: %w", err)
	}

	workersNum := runtime.GOMAXPROCS(0)
	workers := make([]chan datagramMessageInfo, workersNum)
	for i := range workers {
		workers[i] = make(chan datagramMessageInfo, 1000)
	}

	br := &Router{
		ctx:         ctx,
		packetsPool: dgmessage.NewDGMessagePool(math.MaxUint16),

		routingTable: routingtable.New(),
		firewall:     firewall.New(),
		toIface:      make(chan *dgmessage.DatagramMessage, 1000),

		gatewayAddr:   gatewayAddr,
		globalNetwork: globalNetwork,

		shardedWorkers: workers,

		routingsubs:  make(map[chan RouterEvent]struct{}),
		firewallsubs: make(map[chan FirewallEvent]struct{}),
		userRules:    userrules.New(),
		pins:         make(map[uint64]pin),
	}
	return br, nil
}

// SetExitSender регистрирует примитив отправки датаграммы ноде-выходу (mesh).
func (r *Router) SetExitSender(f func(endpoint string, data []byte) error) {
	r.exitMu.Lock()
	r.exitFn = f
	r.exitMu.Unlock()
}

// SetDomainPolicy подключает доменные правила и DNS-кэш.
func (r *Router) SetDomainPolicy(rules *domainrules.Table, cache *dnsproxy.Cache) {
	r.domainRules = rules
	r.domainCache = cache
}

func (r *Router) ReplaceDomainRules(entries []domainrules.Entry) {
	if r.domainRules != nil {
		r.domainRules.ReplaceAll(entries)
	}
}

func (r *Router) SetDNSHandler(h UDPDNSHandler) {
	r.dnsHandler = h
}

func (r *Router) lookupPolicy(src, dst uint32) (string, string) {
	ipAction, ipExit, ipTier := r.userRules.LookupWithTier(src, dst)
	if ipAction == userrules.ActionDeny {
		return userrules.ActionDeny, ""
	}
	if action, exit, ok := r.getPin(src, dst); ok {
		return action, exit
	}
	if r.domainRules == nil || r.domainCache == nil {
		return ipAction, ipExit
	}

	// Если хотя бы один домен на этом IP запрещён — IP блокируется.
	for _, domain := range r.domainCache.GlobalDomains(dst) {
		if rule, ok := r.domainRules.Lookup(src, domain); ok && rule.Action == userrules.ActionDeny {
			return userrules.ActionDeny, ""
		}
	}

	var best *domainrules.Rule
	for _, hit := range r.domainCache.DomainsForClient(src, dst) {
		rule, ok := r.domainRules.Lookup(src, hit.Domain)
		if !ok {
			continue
		}
		if best == nil || betterDomain(rule, *best) {
			ruleCopy := rule
			best = &ruleCopy
		}
	}
	if best != nil && best.Tier <= ipTier {
		r.setPin(src, dst, best.Action, best.Exit)
		return best.Action, best.Exit
	}
	return ipAction, ipExit
}

func betterDomain(a, b domainrules.Rule) bool {
	if a.Tier != b.Tier {
		return a.Tier < b.Tier
	}
	if a.GroupPriority != b.GroupPriority {
		return a.GroupPriority < b.GroupPriority
	}
	return a.Priority < b.Priority
}

func (r *Router) getPin(src, dst uint32) (string, string, bool) {
	key := uint64(src)<<32 | uint64(dst)
	r.pinsMu.Lock()
	defer r.pinsMu.Unlock()
	p, ok := r.pins[key]
	if !ok {
		return "", "", false
	}
	if time.Now().After(p.expires) {
		delete(r.pins, key)
		return "", "", false
	}
	return p.action, p.exit, true
}

func (r *Router) setPin(src, dst uint32, action, exit string) {
	key := uint64(src)<<32 | uint64(dst)
	r.pinsMu.Lock()
	r.pins[key] = pin{action: action, exit: exit, expires: time.Now().Add(10 * time.Minute)}
	r.pinsMu.Unlock()
}

// sudo sysctl -w net.core.default_qdisc=fq                                                                                                                                                                                                             ✔
// sudo sysctl -w net.ipv4.tcp_congestion_control=bbr
func (r *Router) Run() {
	// Launch sharded workers
	var wg sync.WaitGroup

	for _, shardChan := range r.shardedWorkers {
		wg.Go(func() {
			for {
				select {
				case <-r.ctx.Done():
					return
				case packet := <-shardChan:
					switch packet.From {
					case fromTun:
						r.handleTunPacketInternal(packet.Msg)
					case fromMesh:
						r.handleMeshPacketInternal(packet.Msg)
					case fromTransport:
						r.handleTransportPacketInternal(packet.Msg)
					}
				}
			}
		})
	}

	wg.Wait()
}

// deliverToIface отдаёт пакет писателю TUN без блокировки шардового воркера.
// toIface — канал на 1000; если TUN не успевает, прямая отправка подвешивала
// все шарды (и mesh-транзит) на неопределённый срок. При переполнении дропаем
// и считаем метрику: для интернет-трафика это эквивалент переполнения очереди,
// но без остановки остального роутинга.
func (r *Router) deliverToIface(packet *dgmessage.DatagramMessage) {
	select {
	case r.toIface <- packet:
	default:
		metrics.ObserveIfaceDrop(metrics.DirOut)
		packet.Free()
	}
}

// Packets handling methods
func (r *Router) handleTunPacketInternal(packet *dgmessage.DatagramMessage) {
	peer, ex := r.routingTable.GetByIP(packet.HoleInfo.DstIP)
	if !ex {
		packet.Free()
		return
	}
	if shaped, ok := peer.(*routingtable.ShapedRoute); ok {
		// PushLimited забирает владение пакетом и освобождает его на всех
		// путях (включая ошибку). Повторный Free здесь приводил к double-free.
		if err := shaped.PushLimited(packet); err != nil {
			log.Printf("failed to push to shaped connection: %v", err)
		}
	} else {
		err := peer.SendDatagram(packet.Data)
		if err != nil {
			log.Printf("failed to send datagram from mesh %d: %v", len(packet.Data), err)
		}
		packet.Free()
	}
}
func (r *Router) handleMeshPacketInternal(packet *dgmessage.DatagramMessage) {
	// Пакет из другой ноды с адресом вне overlay — это client-exit: узел-выход
	// выпускает его в интернет (NAT) у себя.
	if !r.globalNetwork.Contains(packet.HoleInfo.DstIP) {
		if isForbiddenEgress(packet.HoleInfo.DstIP) {
			packet.Free()
			return
		}
		r.deliverToIface(packet)
		return
	}

	// Mesh-ноды — доверенный контур (общий секрет флота). Для пакетов,
	// пришедших из меша к локальному клиенту, RuleCheck здесь не является
	// границей безопасности; при необходимости его можно включить как
	// дополнительную проверку, но это ужесточит client→client семантику.
	if packet.HoleInfo.Protocol != "" {
		r.firewall.Holepunch(packet.HoleInfo, time.Minute)
	}

	peer, ex := r.routingTable.GetByIP(packet.HoleInfo.DstIP)
	if !ex {
		packet.Free()
		return
	}

	if shaped, ok := peer.(*routingtable.ShapedRoute); ok {
		if err := shaped.PushLimited(packet); err != nil {
			log.Printf("failed to push to shaped connection: %v", err)
		}
	} else {
		err := peer.SendDatagram(packet.Data)
		if err != nil {
			log.Printf("failed to send datagram from mesh %d: %v", len(packet.Data), err)
		}
		packet.Free()
	}
}
func (r *Router) handleTransportPacketInternal(packet *dgmessage.DatagramMessage) {
	srcPeer, ex := r.routingTable.GetByIP(packet.HoleInfo.SrcIP)
	// Check rate limits
	if ex {
		if shaped, ok := srcPeer.(*routingtable.ShapedRoute); ok {
			if !shaped.IsAllowed(uint64(len(packet.Data))) {
				packet.Free()
				return
			}
		}
	}

	if r.dnsHandler != nil && packet.HoleInfo.Protocol == "udp" && packet.HoleInfo.DstPort == 53 && packet.HoleInfo.DstIP != r.gatewayAddr {
		if payload := udpPayload(packet.Data); len(payload) > 0 {
			if answer := r.dnsHandler.HandleUDPQuery(packet.HoleInfo.SrcIP, payload); len(answer) > 0 {
				if out := buildUDPResponse(packet, answer); out != nil {
					if peer, ok := r.routingTable.GetByIP(packet.HoleInfo.SrcIP); ok {
						_ = peer.SendDatagram(out)
					}
				}
				packet.Free()
				return
			}
		}
	}

	if packet.HoleInfo.DstIP == r.gatewayAddr {
		r.deliverToIface(packet) // TUN (локальные сервисы ноды: DNS и т.п.)
		return
	}
	if !r.globalNetwork.Contains(packet.HoleInfo.DstIP) {
		// Выход в интернет. Режем зарезервированные диапазоны, чтобы клиент не мог
		// достучаться до loopback, LAN хостовой машины и облачных metadata-эндпоинтов
		// (169.254.169.254 — кража кредов инстанса).
		if isForbiddenEgress(packet.HoleInfo.DstIP) {
			packet.Free()
			return
		}
		// Policy: deny / exit / direct.
		action, ep := r.lookupPolicy(packet.HoleInfo.SrcIP, packet.HoleInfo.DstIP)
		switch action {
		case userrules.ActionDeny:
			packet.Free()
			return
		case userrules.ActionExit:
			if ep != "" {
				r.exitMu.RLock()
				fn := r.exitFn
				r.exitMu.RUnlock()
				if fn != nil {
					if err := fn(ep, packet.Data); err != nil {
						log.Printf("failed to forward egress to exit %s: %v", ep, err)
					}
					packet.Free()
					return
				}
			}
		}
		r.deliverToIface(packet) // TUN → интернет через NAT (direct)
		return
	}
	hi := dgmessage.HoleInfo{
		SrcIP:    packet.HoleInfo.SrcIP,
		DstIP:    packet.HoleInfo.DstIP,
		SrcPort:  packet.HoleInfo.SrcPort,
		DstPort:  packet.HoleInfo.DstPort,
		Protocol: packet.HoleInfo.Protocol,
	}
	if !r.firewall.RuleCheck(hi) {
		packet.Free()
		return
	}
	r.firewall.Holepunch(hi, time.Minute)

	peer, ex := r.routingTable.GetByIP(packet.HoleInfo.DstIP)
	if !ex {
		packet.Free()
		return
	}
	if shaped, ok := peer.(*routingtable.ShapedRoute); ok {
		if err := shaped.PushLimited(packet); err != nil {
			log.Printf("failed to push to shaped connection: %v", err)
		}
		return
	}
	err := peer.SendDatagram(packet.Data)
	if err != nil {
		log.Printf("failed to send datagram to mesh: %v", err)
	}
	packet.Free()
}

// isForbiddenEgress отсекает адреса, куда VPN-клиент не должен уметь ходить наружу:
// this-network, loopback, link-local (включая облачный metadata 169.254.169.254),
// приватные сети хоста (RFC1918), multicast и reserved. Мешевые адреса сюда не
// попадают — они отсекаются раньше по globalNetwork.Contains.
// ponytail: денйлист захардкожен. Если деплою нужен доступ клиента в LAN — вынести в конфиг.
func isForbiddenEgress(ip uint32) bool {
	switch {
	case ip>>24 == 0x00: // 0.0.0.0/8
		return true
	case ip>>24 == 0x7F: // 127.0.0.0/8 loopback
		return true
	case ip>>24 == 0x0A: // 10.0.0.0/8
		return true
	case ip>>16 == 0xA9FE: // 169.254.0.0/16 link-local + cloud metadata
		return true
	case ip>>16 == 0xC0A8: // 192.168.0.0/16
		return true
	case ip >= 0xAC100000 && ip <= 0xAC1FFFFF: // 172.16.0.0/12
		return true
	case ip >= 0xC6120000 && ip <= 0xC613FFFF: // 198.18.0.0/15 (proxy local IP pool)
		return true
	case ip >= 0xE0000000: // 224.0.0.0/4 multicast + 240.0.0.0/4 reserved + broadcast
		return true
	default:
		return false
	}
}

// udpPayload возвращает UDP payload из IPv4-пакета.
func udpPayload(data []byte) []byte {
	if len(data) < 20 || data[0]>>4 != 4 || data[9] != 17 {
		return nil
	}
	ihl := int(data[0]&0x0f) * 4
	if len(data) < ihl+8 {
		return nil
	}
	return data[ihl+8:]
}

// buildUDPResponse собирает ответ от исходного destination (например, 8.8.8.8:53)
// обратно клиенту. Нужен для перехвата DNS-запросов, ушедших не на gateway.
func buildUDPResponse(orig *dgmessage.DatagramMessage, payload []byte) []byte {
	srcIP := orig.HoleInfo.DstIP
	dstIP := orig.HoleInfo.SrcIP
	srcPort := orig.HoleInfo.DstPort
	dstPort := orig.HoleInfo.SrcPort
	total := 20 + 8 + len(payload)
	pkt := make([]byte, total)

	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	pkt[8] = 64
	pkt[9] = 17
	binary.BigEndian.PutUint32(pkt[12:16], srcIP)
	binary.BigEndian.PutUint32(pkt[16:20], dstIP)
	binary.BigEndian.PutUint16(pkt[10:12], checksum16(pkt[:20], 0))

	udp := pkt[20:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	copy(udp[8:], payload)

	pseudo := make([]byte, 12)
	binary.BigEndian.PutUint32(pseudo[0:4], srcIP)
	binary.BigEndian.PutUint32(pseudo[4:8], dstIP)
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(8+len(payload)))
	cs := checksum16(append(pseudo, udp...), 0)
	if cs == 0 {
		cs = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], cs)
	return pkt
}

func checksum16(data []byte, initial uint32) uint16 {
	sum := initial
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
