package mesh

import (
	"context"
	"fmt"
	"net"
	"strconv"
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

	n.outboundMu.Lock()
	pc := n.outbound[key]
	if pc == nil {
		pc, err = n.transport.Dial(ctx, key)
		if err != nil {
			n.outboundMu.Unlock()
			return err
		}
		if pc.ID() == n.localID {
			_ = pc.Close()
			n.outboundMu.Unlock()
			return fmt.Errorf("dialed self %s", endpoint)
		}
		n.outbound[key] = pc
		n.engine.HandleConnection(ctx, pc)
	}
	n.outboundMu.Unlock()

	return pc.SendDatagram(data)
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
			n.engine.HandleConnection(n.ctx, conn)
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
	refresh := time.NewTicker(30 * time.Second)
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

// supervise держит одно соединение к addr и переподключается при обрыве.
func (n *MeshNode) supervise(ctx context.Context, addr string) {
	backoff := 2 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}

		pc, err := n.transport.Dial(ctx, addr)
		if err != nil {
			time.Sleep(backoff)
			continue
		}

		// Случайно «дозвонились до себя» (например, свой IP из k8s-DNS).
		if pc.ID() == n.localID {
			_ = pc.Close()
			return
		}

		n.outboundMu.Lock()
		n.outbound[addr] = pc
		n.outboundMu.Unlock()
		n.engine.HandleConnection(ctx, pc)

		select {
		case <-ctx.Done():
			n.dropOutbound(addr, pc)
			return
		case <-pc.Context().Done():
			// соединение умерло — переподключаемся
		}
		n.dropOutbound(addr, pc)
		time.Sleep(backoff)
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
