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

	"github.com/liberator-vpn/liberator-node-go/internal/appconfig"
	"github.com/liberator-vpn/liberator-node-go/internal/infra/ipapi"

	"github.com/liberator-vpn/liberator-node-go/internal/utils/safemap"
	"github.com/liberator-vpn/liberator-node-go/pkg/iface"
	"github.com/liberator-vpn/liberator-node-go/pkg/mesh"
	"github.com/liberator-vpn/liberator-node-go/pkg/router"
	"github.com/liberator-vpn/liberator-node-go/pkg/services/firewallmanager"
	"github.com/liberator-vpn/liberator-node-go/pkg/services/peersmanager"
	"github.com/liberator-vpn/liberator-node-go/pkg/transport"
	"github.com/liberator-vpn/liberator-node-go/pkg/transport/awg"

	"google.golang.org/grpc"

	grpcctrl "github.com/liberator-vpn/liberator-node-go/pkg/api/controllers/grpc"
	httpctrl "github.com/liberator-vpn/liberator-node-go/pkg/api/controllers/http"
)

type App struct {
	ctx    context.Context
	cancel context.CancelFunc
	cfg    *appconfig.AppConfig

	firewallManager *firewallmanager.Firewallmanager
	peersManager    *peersmanager.PeersManager

	router *router.Router

	node       *mesh.MeshNode
	nodeID     string
	tunIface   *iface.TUNIface
	transports safemap.Safemap[string, transport.Transport]

	// Grpc
	grpcLis    net.Listener
	grpcServer *grpc.Server

	// Http
	httpMux    *http.ServeMux
	httpServer *http.Server

	ipInfo *ipapi.IPInfo
}

// nodeIdentity возвращает стабильную идентичность ноды. node_id в конфиге больше
// нет: в k8s его выставляет окружение (downward API) — POD_NAME/POD_UID.
func nodeIdentity() string {
	for _, k := range []string{"POD_NAME", "POD_UID", "HOSTNAME"} {
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
		ctx:        ctx,
		cancel:     cancel,
		cfg:        cfg,
		transports: safemap.New[string, transport.Transport](),
	}
	initialized := false
	defer func() {
		if !initialized {
			app.closeResources()
		}
	}()
	var err error
	// Один общий secret защищает control-plane и QUIC-пул между нодами.
	secret := cfg.Auth.Secret
	if err := validateSecret(secret); err != nil {
		return nil, err
	}
	nodeID := nodeIdentity()
	app.nodeID = nodeID
	// Overlay-адресация приходит из конфига (config-фид), а не из сертификата.
	// global_cidr общий для всех нод; gateway_addr — единственный overlay IP ноды.
	gatewayAddr := cfg.VPN.GatewayAddr
	globalNet := cfg.VPN.GlobalCIDR
	if gatewayAddr == "" || globalNet == "" {
		return nil, fmt.Errorf("vpn.gateway_addr and vpn.global_cidr must be set")
	}
	// TUN/аллокация используют префикс общей overlay-сети.
	nodeCIDR := gatewayCIDR(gatewayAddr, globalNet)

	// Control-plane gRPC (внутри куб-сети — без TLS, доступ по секрету).
	app.grpcLis, err = net.Listen("tcp", cfg.Api.Grpc.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to launch grpc server: %w", err)
	}

	app.grpcServer = grpc.NewServer(
		grpc.UnaryInterceptor(grpcctrl.UnaryAuthInterceptor(secret)),
	)

	app.httpMux = http.NewServeMux()
	app.httpServer = &http.Server{
		Addr:    cfg.Api.Http.ListenAddr,
		Handler: httpctrl.HTTPAuthMiddleware(secret, app.httpMux),
	}

	// Network stuff
	if app.router, err = router.New(ctx, gatewayAddr, globalNet); err != nil {
		return nil, fmt.Errorf("failed to create router: %v", err)
	}

	if app.node, err = mesh.New(ctx, cfg.Mesh, secret, app.router); err != nil {
		return nil, fmt.Errorf("failed to create mesh node: %v", err)
	}

	// managers
	app.firewallManager = firewallmanager.New(app.router, nodeID)
	app.peersManager = peersmanager.New(app.ctx, app.firewallManager)

	// Get current server ip and location
	ipInfo, err := ipapi.GetIpInfo(ctx)
	if err != nil {
		log.Printf("failed to update err: %v", err)
		ipInfo = &ipapi.IPInfo{
			CountryCode: cfg.CountryCode,
		}
	}
	app.ipInfo = ipInfo

	// Create tun iface
	if app.tunIface, err = iface.NewTUN(
		ctx,
		cfg.TunConfig,
		app.router,
		nodeCIDR,
	); err != nil {
		return nil, fmt.Errorf("failed to create tun iface: %w", err)
	}

	// Build transports
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

			trp, err = awg.New(
				ctx,
				icfg,
				app.router,
				nodeID,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to create transport %s: %w", name, err)
			}
		default:
			return nil, fmt.Errorf("unknown transport type: %s", typ)
		}
		app.transports.Set(name, trp)
		app.peersManager.RegisterTransport(name, trp)
		// Провижим желаемых клиентов (config-фид) на этот транспорт.
		if err := app.peersManager.ApplyClients(ctx, name, cfg.VPN.Clients); err != nil {
			return nil, fmt.Errorf("failed to provision clients on transport %s: %w", name, err)
		}
	}
	initialized = true
	return app, nil
}

func (app *App) Run() (runErr error) {
	defer func() {
		app.stopRuntime()
	}()

	// Registering controllers
	grpcctrl.RegisterNodeService(app.grpcServer, app.nodeID, *app.ipInfo, app.transports)
	grpcctrl.RegisterMeshService(app.grpcServer, app.node)
	grpcctrl.RegisterRouterService(app.grpcServer, app.router)

	httpctrl.RegisterMeshNodeService(app.httpMux, app.node)
	httpctrl.RegisterRouterService(app.httpMux, app.router)

	var workers sync.WaitGroup
	workers.Go(app.router.Run)
	workers.Go(app.node.Run)
	workers.Go(app.tunIface.Run)

	app.transports.Foreach(func(_ string, t transport.Transport) {
		workers.Go(t.Run)
	})

	serveErr := make(chan error, 2)
	go func() {
		serveErr <- app.grpcServer.Serve(app.grpcLis)
	}()
	go func() {
		err := app.httpServer.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- fmt.Errorf("HTTP server error: %w", err)
			return
		}
		serveErr <- nil
	}()

	var grpcErr error
	serveFinished := false
	select {
	case <-app.ctx.Done():
	case grpcErr = <-serveErr:
		serveFinished = true
		app.cancel()
	}

	app.stopRuntime()
	workers.Wait()

	if !serveFinished {
		grpcErr = <-serveErr
	}
	if grpcErr != nil && !errors.Is(grpcErr, grpc.ErrServerStopped) {
		return fmt.Errorf("gRPC server stopped: %w", grpcErr)
	}

	return nil
}

func (app *App) stopRuntime() {
	app.cancel()
	if app.node != nil {
		app.node.Close()
	}
	if app.grpcServer != nil {
		app.grpcServer.Stop()
	}
	if app.grpcLis != nil {
		_ = app.grpcLis.Close()
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
