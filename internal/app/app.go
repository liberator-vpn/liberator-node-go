package app

import (
	"context"
	"database/sql"
	"fmt"
	"liberator-node-go/internal/appconfig"
	"log"
	"net"
	"sync"

	"liberator-node-go/internal/utils/safemap"
	"liberator-node-go/pkg/firewall"
	"liberator-node-go/pkg/iface"
	"liberator-node-go/pkg/mesh"
	"liberator-node-go/pkg/router"
	"liberator-node-go/pkg/routingtable"
	"liberator-node-go/pkg/services/firewallmanager"
	"liberator-node-go/pkg/services/peersmanager"
	"liberator-node-go/pkg/transport"
	"liberator-node-go/pkg/transport/awg"

	_ "github.com/mattn/go-sqlite3"
	"google.golang.org/grpc"

	grpcctrl "liberator-node-go/pkg/api/controllers/grpc"
)

type App struct {
	ctx context.Context
	cfg *appconfig.AppConfig

	db *sql.DB

	routingTable routingtable.RoutingTable
	firewall     firewall.FirewallEngine

	firewallManager *firewallmanager.Firewallmanager
	peersManager    *peersmanager.PeersManager

	router *router.Router

	node       *mesh.MeshNode
	tunIface   *iface.TUNIface
	transports safemap.Safemap[string, transport.Transport]

	grpcLis    net.Listener
	grpcServer *grpc.Server
}

func New(ctx context.Context, cfg *appconfig.AppConfig) (*App, error) {
	app := &App{
		ctx:          ctx,
		cfg:          cfg,
		routingTable: routingtable.New(),
		firewall:     firewall.New(),
		transports:   safemap.New[string, transport.Transport](),
		grpcServer:   grpc.NewServer(),
	}
	var err error

	app.grpcLis, err = net.Listen("tcp", cfg.Api.Grpc.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to launch grpc server: %w", err)
	}

	if app.db, err = sql.Open("sqlite3", app.cfg.Database.File); err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}
	if err = app.db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %v", err)
	}

	app.firewallManager = firewallmanager.New(app.firewall, app.db)
	app.peersManager = peersmanager.New(app.db, app.firewallManager)

	if app.router, err = router.New(ctx, cfg.Router, app.routingTable, app.firewall); err != nil {
		return nil, fmt.Errorf("failed to create router: %v", err)
	}

	if app.node, err = mesh.New(ctx, cfg.Mesh, app.router); err != nil {
		return nil, fmt.Errorf("failed to create mesh node: %v", err)
	}

	// Create tun iface
	if app.tunIface, err = iface.NewTUN(
		ctx,
		cfg.TunConfig,
		app.router,
		cfg.Router.CIDR,
	); err != nil {
		return nil, fmt.Errorf("failed to create tun iface: %w", err)
	}

	// Build transports
	for name, iconf := range cfg.Router.Transports {
		if app.transports.Exists(name) {
			return nil, fmt.Errorf("duplicated ingress name: %s", name)
		}
		typ, ex := iconf["type"]
		if !ex {
			return nil, fmt.Errorf("type for ingress %s is not provided", name)
		}

		var trp transport.Transport
		switch typ {
		case "awg":
			icfg, err := awg.ParseConfig(iconf)
			if err != nil {
				return nil, fmt.Errorf("failed to parse ingress %s config: %v", name, err)
			}

			trp, err = awg.New(
				ctx,
				icfg,
				app.router,
				app.node.NodeID(),
			)
			if err != nil {
				return nil, fmt.Errorf("failed to create ingress %s: %w", name, err)
			}
		default:
			return nil, fmt.Errorf("unknown ingress type: %s", typ)
		}
		app.transports.Set(name, trp)
		app.peersManager.RegisterTransport(name, trp)
	}
	return app, nil
}

func (app *App) Run() error {
	// Registering controllers
	grpcctrl.RegisterFirewallService(app.grpcServer, app.firewallManager)
	grpcctrl.RegisterPeerService(app.grpcServer, app.peersManager)

	if err := app.firewallManager.Start(app.ctx); err != nil {
		return fmt.Errorf("failed to start firewall manager: %v", err)
	}

	if err := app.peersManager.Start(app.ctx); err != nil {
		return fmt.Errorf("failed to start peers manager: %v", err)
	}

	var wg sync.WaitGroup
	wg.Go(app.router.Run)
	wg.Go(app.node.Run)
	wg.Go(app.tunIface.Run)
	app.transports.Foreach(func(_ string, t transport.Transport) {
		wg.Go(t.Run)
	})

	wg.Go(func() {
		if err := app.grpcServer.Serve(app.grpcLis); err != nil {
			log.Fatalf("failed to start grpc server: %w", err)
		}
	})

	wg.Wait()

	return nil
}
