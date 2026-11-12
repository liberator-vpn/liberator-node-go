package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/liberator-vpn/liberator-node-go/internal/appconfig"

	"github.com/liberator-vpn/liberator-node-go/internal/metrics"
	"github.com/liberator-vpn/liberator-node-go/internal/utils/safemap"
	"github.com/liberator-vpn/liberator-node-go/pkg/dnsproxy"
	"github.com/liberator-vpn/liberator-node-go/pkg/domainrules"
	"github.com/liberator-vpn/liberator-node-go/pkg/iface"
	"github.com/liberator-vpn/liberator-node-go/pkg/mesh"
	"github.com/liberator-vpn/liberator-node-go/pkg/router"
	"github.com/liberator-vpn/liberator-node-go/pkg/services/peersmanager"
	"github.com/liberator-vpn/liberator-node-go/pkg/transport"
	"github.com/liberator-vpn/liberator-node-go/pkg/transport/awg"
	"github.com/liberator-vpn/liberator-node-go/pkg/transport/xray"
)

type App struct {
	ctx    context.Context
	cancel context.CancelFunc
	cfg    *appconfig.AppConfig

	router *router.Router

	node       *mesh.MeshNode
	nodeID     string
	apiNodeID  string // node_id, выданный API при enrollment
	apiSecret  string // per-node secret для /v1/node/*
	tunIface   *iface.TUNIface
	transports safemap.Safemap[string, transport.Transport]
	// protocol -> имя транспорта. Позволяет направлять сессии из /state
	// в awg/vless/hysteria2, а не в один «последний зарегистрированный».
	protocolTransport map[string]string

	peersManager *peersmanager.PeersManager

	// Установленные firewall-правила (по стабильному RuleID).
	fwRules map[uint64]struct{}

	domainRules *domainrules.Table
	dnsCache    *dnsproxy.Cache
	dnsServer   *dnsproxy.Server

	// Только /healthz и /metrics (нода пассивная, без control-plane).
	httpMux    *http.ServeMux
	httpServer *http.Server
}

// nodeIdentity возвращает стабильную идентичность ноды. node_id в конфиге нет:
// в k8s её выставляет окружение. LIBERATOR_NODE_ID/NODE_NAME приоритетнее
// POD_NAME/POD_UID, потому что имя пода меняется при рестарте, а API
// upsert-ит ноду по hostname — иначе каждый рестарт создавал бы новую ноду.
func nodeIdentity() string {
	for _, k := range []string{"LIBERATOR_NODE_ID", "NODE_NAME", "POD_NAME", "POD_UID", "HOSTNAME"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return "node"
}

// gatewayCIDR возвращает адрес ноды с префиксом общей overlay-сети,
// напр. gateway "10.1.0.1" + global "10.0.0.0/8" -> "10.1.0.1/8".
func gatewayCIDR(gatewayAddr, globalCIDR string) string {
	_, ipNet, err := net.ParseCIDR(globalCIDR)
	if err != nil {
		return gatewayAddr
	}
	ones, _ := ipNet.Mask.Size()
	return fmt.Sprintf("%s/%d", gatewayAddr, ones)
}

// validateSecret отбраковывает пустые, слишком короткие и заведомо дефолтные секреты.
func validateSecret(secret string) error {
	if len(secret) < 16 {
		return fmt.Errorf("auth.secret_key must be at least 16 chars; generate a random one")
	}
	weak := map[string]struct{}{"sraka": {}, "secret": {}, "changeme": {}, "password": {}}
	if _, bad := weak[strings.ToLower(secret)]; bad {
		return fmt.Errorf("auth.secret_key is a known weak/default value; set a random secret")
	}
	return nil
}

func New(ctx context.Context, cfg *appconfig.AppConfig) (*App, error) {
	ctx, cancel := context.WithCancel(ctx)
	app := &App{
		ctx:               ctx,
		cancel:            cancel,
		cfg:               cfg,
		transports:        safemap.New[string, transport.Transport](),
		protocolTransport: make(map[string]string),
		fwRules:           make(map[uint64]struct{}),
	}
	initialized := false
	defer func() {
		if !initialized {
			app.closeResources()
		}
	}()
	var err error

	// Общий secret защищает QUIC-пул между нодами (входящего control-plane нет).
	secret := cfg.Auth.Secret
	if err := validateSecret(secret); err != nil {
		return nil, err
	}
	nodeID := nodeIdentity()
	app.nodeID = nodeID

	// global_cidr и gateway ноды — источник истины API. При наличии API
	// загружаем сохранённую identity или enroll'имся по одноразовому токену.
	if cfg.API.BaseURL != "" {
		identity, err := app.ensureIdentity(ctx)
		if err != nil {
			return nil, err
		}
		app.apiNodeID = identity.NodeID
		app.apiSecret = identity.Secret
		if identity.GatewayAddr != "" {
			cfg.VPN.GatewayAddr = identity.GatewayAddr
		}
		if identity.GlobalCIDR != "" {
			cfg.VPN.GlobalCIDR = identity.GlobalCIDR
		}
	}

	// Bootstrap overlay: global_cidr общий для всех нод; gateway_addr — локальный
	// overlay IP ноды (в проде API выдаёт gateway из того же пула, что и клиенты).
	gatewayAddr := cfg.VPN.GatewayAddr
	globalNet := cfg.VPN.GlobalCIDR
	if gatewayAddr == "" || globalNet == "" {
		return nil, fmt.Errorf("vpn.gateway_addr and vpn.global_cidr must be set")
	}
	nodeCIDR := gatewayCIDR(gatewayAddr, globalNet)

	if app.router, err = router.New(ctx, gatewayAddr, globalNet); err != nil {
		return nil, fmt.Errorf("failed to create router: %v", err)
	}
	app.domainRules = domainrules.New()
	app.dnsCache = dnsproxy.NewCache(dnsproxy.CacheConfig{
		TTL: cfg.DNS.Cache.TTL, MaxEntries: cfg.DNS.Cache.MaxEntries,
	})
	app.router.SetDomainPolicy(app.domainRules, app.dnsCache)
	if cfg.DNS.Enabled {
		listenIP := cfg.DNS.ListenAddr
		if listenIP == "" || listenIP == "auto" {
			listenIP = gatewayAddr
		}
		dnsSrv, err := dnsproxy.NewServer(ctx, dnsproxy.ServerConfig{
			ListenAddr: listenIP,
			ListenPort: cfg.DNS.ListenPort,
			Upstreams:  cfg.DNS.Upstreams,
			Timeout:    cfg.DNS.Timeout,
		}, app.dnsCache)
		if err != nil {
			return nil, fmt.Errorf("failed to create DNS proxy: %w", err)
		}
		app.dnsServer = dnsSrv
		app.router.SetDNSHandler(dnsSrv)
	}

	if app.node, err = mesh.New(ctx, cfg.Mesh, secret, app.router); err != nil {
		return nil, fmt.Errorf("failed to create mesh node: %v", err)
	}
	// Еджест client-exit: не-overlay трафик клиента форвардится на ноду-выход.
	app.router.SetExitSender(func(endpoint string, data []byte) error {
		return app.node.SendTo(app.ctx, endpoint, data)
	})
	// remote-клиенты (client→client) mesh добавляет в routing-таблицу роутера.
	app.node.SetRemoteRouting(app.router.AddRemoteRoutingObject, app.router.DeleteRemoteRoutingObject)

	app.peersManager = peersmanager.New(app.ctx)

	if app.tunIface, err = iface.NewTUN(ctx, cfg.TunConfig, app.router, nodeCIDR); err != nil {
		return nil, fmt.Errorf("failed to create tun iface: %w", err)
	}

	for name, iconf := range cfg.Router.Transports {
		if app.transports.Exists(name) {
			return nil, fmt.Errorf("duplicated transport name: %s", name)
		}
		typ, ex := iconf["type"]
		if !ex {
			return nil, fmt.Errorf("type for transport %s is not provided", name)
		}

		var trp transport.Transport
		switch typ {
		case "awg":
			icfg, err := awg.ParseConfig(iconf)
			if err != nil {
				return nil, fmt.Errorf("failed to parse transport %s config: %v", name, err)
			}
			trp, err = awg.New(ctx, icfg, app.router, nodeID)
			if err != nil {
				return nil, fmt.Errorf("failed to create transport %s: %w", name, err)
			}
		case "xray":
			// Xray принимает VLESS+REALITY и Hysteria2 (оба — клиентские
			// протоколы) и отдаёт расшифрованный IP-трафик в proxy-TUN,
			// откуда нода забирает его в общий роутер.
			icfg, err := xray.ParseConfig(iconf)
			if err != nil {
				return nil, fmt.Errorf("failed to parse transport %s config: %v", name, err)
			}
			trp, err = xray.New(ctx, icfg, app.router, nodeID)
			if err != nil {
				return nil, fmt.Errorf("failed to create transport %s: %w", name, err)
			}
		default:
			return nil, fmt.Errorf("unknown transport type: %s", typ)
		}
		app.transports.Set(name, trp)
		app.peersManager.RegisterTransport(name, trp)
		for _, protocol := range trp.Protocols() {
			if existing, ok := app.protocolTransport[protocol]; ok && existing != name {
				return nil, fmt.Errorf("protocol %q is served by both %q and %q", protocol, existing, name)
			}
			app.protocolTransport[protocol] = name
		}
	}

	app.httpMux = http.NewServeMux()
	app.httpMux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	app.httpMux.Handle("/metrics", metrics.Handler())
	app.httpServer = &http.Server{
		Addr:    cfg.Server.ListenAddr,
		Handler: app.httpMux,
	}

	metrics.SetActiveClients(0)

	initialized = true
	return app, nil
}

func (app *App) Run() error {
	defer app.stopRuntime()

	var workers sync.WaitGroup
	workers.Go(app.router.Run)
	workers.Go(app.node.Run)
	workers.Go(app.tunIface.Run)
	if app.dnsServer != nil {
		workers.Go(app.dnsServer.Run)
	}
	app.transports.Foreach(func(_ string, t transport.Transport) {
		workers.Go(t.Run)
	})
	workers.Go(func() { app.metricsLoop(app.ctx) })
	app.peersManager.StartUsageCollector(app.ctx)
	// Пассивный контур к API (если настроен): регистрация + sync желаемого состояния.
	if app.cfg.API.BaseURL != "" {
		workers.Go(func() { app.syncLoop(app.ctx) })
	}

	serveErr := make(chan error, 1)
	go func() {
		err := app.httpServer.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- fmt.Errorf("HTTP server error: %w", err)
			return
		}
		serveErr <- nil
	}()

	select {
	case <-app.ctx.Done():
	case err := <-serveErr:
		if err != nil {
			return err
		}
	}

	app.stopRuntime()
	workers.Wait()
	return nil
}

// metricsLoop периодически обновляет калибруемые gauge-метрики.
func (app *App) metricsLoop(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if app.node != nil {
				metrics.SetConnectedPeers(app.node.CountConnections())
			}
		}
	}
}

func (app *App) stopRuntime() {
	app.cancel()
	if app.dnsServer != nil {
		app.dnsServer.Close()
	}
	// Транспорты могут владеть TUN/dummy/policy-routing и дочерним Xray.
	// Закрываем их и на аварийном пути app.New, когда Run ещё не стартовал.
	app.transports.Foreach(func(_ string, t transport.Transport) {
		if c, ok := t.(interface{ Close() }); ok {
			c.Close()
		}
	})
	if app.node != nil {
		app.node.Close()
	}
	if app.httpServer != nil {
		_ = app.httpServer.Close()
	}
	// TUN и правила iptables переживают процесс, поэтому их надо снять на любом выходе.
	if app.tunIface != nil {
		if err := app.tunIface.Close(); err != nil {
			log.Printf("failed to close tun iface: %v", err)
		}
	}
}

func (app *App) closeResources() {
	app.stopRuntime()
}
