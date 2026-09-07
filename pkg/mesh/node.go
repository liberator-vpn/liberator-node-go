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
	}, nil
}

func (n *MeshNode) NodeID() string { return n.localID }

func (n *MeshNode) CountConnections() int { return len(n.registry.ListActive()) }
func (n *MeshNode) ListenAddress() net.Addr {
	return n.transport.Addr()
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
		want := n.discoveredPeers(ctx)
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

// discoveredPeers возвращает текущий целевой список "host:port" соседних нод.
func (n *MeshNode) discoveredPeers(ctx context.Context) []string {
	addrs := make(map[string]struct{})

	if n.dnsService != "" {
		if ips, err := net.LookupHost(n.dnsService); err == nil {
			port := strconv.Itoa(n.dnsPort)
			for _, ip := range ips {
				addrs[net.JoinHostPort(ip, port)] = struct{}{}
			}
		}
	}
	for _, s := range n.static {
		if s != "" {
			addrs[s] = struct{}{}
		}
	}

	out := make([]string, 0, len(addrs))
	for a := range addrs {
		out = append(out, a)
	}
	return out
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

		n.engine.HandleConnection(ctx, pc)

		select {
		case <-ctx.Done():
			return
		case <-pc.Context().Done():
			// соединение умерло — переподключаемся
		}
		time.Sleep(backoff)
	}
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
