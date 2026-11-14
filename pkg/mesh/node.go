package mesh

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/liberator-vpn/liberator-node-go/internal/appconfig"
	"github.com/liberator-vpn/liberator-node-go/pkg/mesh/session"
	"github.com/liberator-vpn/liberator-node-go/pkg/mesh/transport"
	"github.com/liberator-vpn/liberator-node-go/pkg/routingtable"
)

// MeshNode — пул длинных QUIC-соединений ко всем остальным нодам. Список нод
// приходит из k8s-DNS (headless-сервис) и/или статического конфига, а не из
// самообучения (gossip). Нода всегда держит по одному соединению на каждую ноду.
type MeshNode struct {
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once

	transport transport.NetworkTransport
	registry  session.Registry
	engine    *session.SessionEngine
	localID   string

	dnsService string
	dnsPort    int
	static     []string

	dynamicMu sync.RWMutex
	dynamic   []string

	outboundMu sync.Mutex
	outbound   map[string]transport.PeerConnection // "ip:port" -> живое соединение

	remoteMu     sync.Mutex
	remotes      map[uint32]string                      // remote virtual IP -> mesh endpoint
	addRemoteObj func(routingtable.RoutingObject) error // методы routing-таблицы роутера
	delRemoteObj func(uint32) error
}

// New собирает пул: transport (QUIC + secret), реестр и движок сессий.
func New(ctx context.Context, cfg appconfig.MeshConfig, secret string, router session.Router) (*MeshNode, error) {
	if cfg.ListenAddr == "" {
		return nil, fmt.Errorf("mesh.listen_addr must be set")
	}
	if secret == "" {
		return nil, fmt.Errorf("mesh secret must be set")
	}

	quicTr, err := transport.NewQuicTransport(cfg.ListenAddr, secret)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize transport: %w", err)
	}

	localID := quicTr.SelfID()
	if localID == "" {
		_ = quicTr.Close()
		return nil, fmt.Errorf("failed to extract local node ID")
	}

	ctx, cancel := context.WithCancel(ctx)
	reg := session.NewRegistry(localID)
	engine := session.NewSessionEngine(reg, router)

	return &MeshNode{
		ctx:        ctx,
		cancel:     cancel,
		transport:  quicTr,
		registry:   reg,
		engine:     engine,
		localID:    localID,
		dnsService: cfg.DNSService,
		dnsPort:    cfg.DNSPort,
		static:     cfg.Static,
		outbound:   make(map[string]transport.PeerConnection),
		remotes:    make(map[uint32]string),
	}, nil
}

func (n *MeshNode) NodeID() string { return n.localID }

func (n *MeshNode) CountConnections() int { return len(n.registry.ListActive()) }

type MeshPeer struct {
	PeerID     string  `json:"peer_id"`
	RemoteAddr string  `json:"remote_addr"`
	RTTMillis  float64 `json:"rtt_ms"`
	Initiator  bool    `json:"initiator"`
	SentBytes  uint64  `json:"sent_bytes"`
	RecvBytes  uint64  `json:"recv_bytes"`
}

// Snapshot возвращает текущие mesh-соединения с RTT из QUIC.
func (n *MeshNode) Snapshot() []MeshPeer {
	sessions := n.registry.ListActive()
	out := make([]MeshPeer, 0, len(sessions))
	for _, s := range sessions {
		if s == nil || s.Conn == nil {
			continue
		}
		rtt := s.Conn.RTT()
		out = append(out, MeshPeer{
			PeerID:     s.PeerID,
			RemoteAddr: s.Conn.RemoteAddr().String(),
			RTTMillis:  float64(rtt.Microseconds()) / 1000.0,
			Initiator:  s.Conn.IsInitiator(),
			SentBytes:  s.Conn.TotalSent(),
			RecvBytes:  s.Conn.TotalRecv(),
		})
	}
	return out
}

// SetDynamicPeers обновляет список соседей, полученный из API directory.
func (n *MeshNode) SetDynamicPeers(peers []string) {
	seen := make(map[string]struct{}, len(peers))
	out := make([]string, 0, len(peers))
	for _, p := range peers {
		p = strings.TrimSpace(p)
		if p == "" || n.isSelfHost(p) {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	n.dynamicMu.Lock()
	n.dynamic = out
	n.dynamicMu.Unlock()
}

func (n *MeshNode) dynamicPeers() []string {
	n.dynamicMu.RLock()
	defer n.dynamicMu.RUnlock()
	return append([]string(nil), n.dynamic...)
}
func (n *MeshNode) ListenAddress() net.Addr {
	return n.transport.Addr()
}

// SendTo отправляет датаграмму на ноду по её QUIC-endpoint (host:port). Если
// соединение к этому адресу уже держится (пул из DNS/static) — переиспользуем,
// иначе устанавливаем. Используется для client→client форвардинга.
func (n *MeshNode) SendTo(ctx context.Context, endpoint string, data []byte) error {
	key, err := n.resolveKey(endpoint)
	if err != nil {
		return err
	}

	// Быстрый путь: соединение уже в пуле. Не держим outboundMu во время
	// Dial — иначе один медленный/недоступный пир блокирует отправку всем.
	n.outboundMu.Lock()
	pc := n.outbound[key]
	n.outboundMu.Unlock()
	if pc != nil {
		return pc.SendDatagram(data)
	}

	pc, err = n.transport.Dial(ctx, key)
	if err != nil {
		return err
	}
	if pc.ID() == n.localID {
		_ = pc.Close()
		return fmt.Errorf("dialed self %s", endpoint)
	}
	created := true
	if err := n.engine.HandleConnection(ctx, pc); err != nil {
		// Соединение отклонено (например, уже есть живая сессия с этим
		// пиром). Не кладём закрытый conn в пул: используем существующую
		// сессию, если она есть, иначе отдаём ошибку.
		if s, ok := n.registry.Get(pc.ID()); ok {
			pc = s.Conn
			created = false
		} else {
			return err
		}
	}

	n.outboundMu.Lock()
	if existing := n.outbound[key]; existing != nil {
		n.outboundMu.Unlock()
		// Пока мы звонили, соединение уже установила другая горутина.
		// Закрываем только то, что создали сами, и только если оно лишнее.
		if created && existing != pc {
			_ = pc.Close()
		}
		return existing.SendDatagram(data)
	}
	n.outbound[key] = pc
	n.outboundMu.Unlock()

	if err := pc.SendDatagram(data); err != nil {
		// Соединение, созданное на data-path, не имеет supervisor'а.
		// Убираем его из пула, чтобы следующая отправка переподключилась.
		n.dropOutbound(key, pc)
		return err
	}
	return nil
}

// resolveKey приводит endpoint к каноническому "ip:port" (резолвит hostname).
func (n *MeshNode) resolveKey(endpoint string) (string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid endpoint %q: %w", endpoint, err)
	}
	if ip := net.ParseIP(host); ip != nil {
		return net.JoinHostPort(host, port), nil
	}
	ips, err := net.LookupHost(host)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("resolve %q: %w", host, err)
	}
	return net.JoinHostPort(ips[0], port), nil
}

// Run запускает accept-цикл и диалер-пул и блокирует до отмены контекста.
func (n *MeshNode) Run() {
	if n.ctx.Err() != nil {
		n.shutdown()
		return
	}

	var wg sync.WaitGroup

	wg.Go(func() {
		for {
			conn, err := n.transport.Accept(n.ctx)
			if err != nil {
				return
			}
			if conn.ID() == n.localID {
				_ = conn.Close()
				continue
			}
			// Дубликаты/self отклоняются внутри engine; отдельная реакция
			// не нужна — соединение уже закрыто.
			_ = n.engine.HandleConnection(n.ctx, conn)
		}
	})

	wg.Go(func() {
		n.runPeersSync(n.ctx)
	})

	<-n.ctx.Done()

	n.shutdown()
	wg.Wait()
}

// runPeersSync периодически обновляет целевой список нод и держит пул соединений.
func (n *MeshNode) runPeersSync(ctx context.Context) {
	refresh := time.NewTicker(10 * time.Second)
	defer refresh.Stop()

	supervisors := make(map[string]context.CancelFunc)

	apply := func() {
		want := n.discoveredPeers()
		wantSet := make(map[string]struct{}, len(want))
		for _, addr := range want {
			wantSet[addr] = struct{}{}
			if _, running := supervisors[addr]; running {
				continue
			}
			sctx, stop := context.WithCancel(ctx)
			supervisors[addr] = stop
			go n.supervise(sctx, addr)
		}
		for addr, stop := range supervisors {
			if _, keep := wantSet[addr]; !keep {
				stop()
				delete(supervisors, addr)
			}
		}
	}

	apply()
	for {
		select {
		case <-ctx.Done():
			return
		case <-refresh.C:
			apply()
		}
	}
}

// discoveredPeers возвращает текущий целевой список "host:port" соседних нод,
// исключая саму ноду (свой IP/loopback), чтобы не держать соединение к себе.
func (n *MeshNode) discoveredPeers() []string {
	addrs := make(map[string]struct{})

	if n.dnsService != "" {
		if ips, err := net.LookupHost(n.dnsService); err == nil {
			port := strconv.Itoa(n.dnsPort)
			for _, ip := range ips {
				if n.isSelfHost(ip) {
					continue
				}
				addrs[net.JoinHostPort(ip, port)] = struct{}{}
			}
		}
	}
	for _, s := range n.static {
		if s == "" || n.isSelfHost(s) {
			continue
		}
		addrs[s] = struct{}{}
	}
	for _, s := range n.dynamicPeers() {
		addrs[s] = struct{}{}
	}

	out := make([]string, 0, len(addrs))
	for a := range addrs {
		out = append(out, a)
	}
	return out
}

var localIPs = sync.OnceValue(func() map[string]struct{} {
	set := make(map[string]struct{})
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				set[ipnet.IP.String()] = struct{}{}
			}
		}
	}
	return set
})

// isSelfHost сообщает, относится ли addr (IP или "host:port") к этой ноде.
func (n *MeshNode) isSelfHost(addr string) bool {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}
	_, ok := localIPs()[ip.String()]
	return ok
}

const (
	superviseBackoffMin = 2 * time.Second
	superviseBackoffMax = 60 * time.Second
)

// supervise держит одно соединение к addr и переподключается при обрыве.
func (n *MeshNode) supervise(ctx context.Context, addr string) {
	backoff := superviseBackoffMin
	for {
		if ctx.Err() != nil {
			return
		}

		// Ключ outbound должен совпадать с тем, что использует SendTo
		// (канонический ip:port), иначе hostname из static-списка и
		// IP из директории создают два соединения к одной ноде.
		key, err := n.resolveKey(addr)
		if err != nil {
			if !sleepCtx(ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}

		pc, err := n.transport.Dial(ctx, key)
		if err != nil {
			if !sleepCtx(ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}

		// Случайно «дозвонились до себя» (например, свой IP из k8s-DNS).
		if pc.ID() == n.localID {
			_ = pc.Close()
			return
		}

		created := true
		if err := n.engine.HandleConnection(ctx, pc); err != nil {
			// Уже есть живая сессия с этим пиром — переиспользуем её.
			if s, ok := n.registry.Get(pc.ID()); ok {
				pc = s.Conn
				created = false
			} else {
				_ = pc.Close()
				if !sleepCtx(ctx, backoff) {
					return
				}
				backoff = nextBackoff(backoff)
				continue
			}
		}

		n.outboundMu.Lock()
		if existing := n.outbound[key]; existing != nil {
			n.outboundMu.Unlock()
			if created && existing != pc {
				_ = pc.Close()
			}
			// Пул уже держит соединение к этому пиру; не плодим второе.
			select {
			case <-ctx.Done():
				return
			case <-existing.Context().Done():
				n.dropOutbound(key, existing)
				backoff = nextBackoff(backoff)
				continue
			}
		}
		n.outbound[key] = pc
		n.outboundMu.Unlock()

		// Соединение установлено — сбрасываем backoff.
		backoff = superviseBackoffMin

		select {
		case <-ctx.Done():
			n.dropOutbound(key, pc)
			return
		case <-pc.Context().Done():
			// соединение умерло — переподключаемся
		}
		n.dropOutbound(key, pc)
		if !sleepCtx(ctx, backoff) {
			return
		}
		backoff = nextBackoff(backoff)
	}
}

func nextBackoff(d time.Duration) time.Duration {
	d *= 2
	if d > superviseBackoffMax {
		return superviseBackoffMax
	}
	return d
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// dropOutbound убирает conn из карты только если это ещё оно.
func (n *MeshNode) dropOutbound(addr string, pc transport.PeerConnection) {
	n.outboundMu.Lock()
	if n.outbound[addr] == pc {
		delete(n.outbound, addr)
	}
	n.outboundMu.Unlock()
}

// Close останавливает пул и освобождает ресурсы.
func (n *MeshNode) Close() { n.shutdown() }

func (n *MeshNode) shutdown() {
	n.closeOnce.Do(func() {
		n.cancel()
		n.registry.Close()
		_ = n.transport.Close()
	})
}
