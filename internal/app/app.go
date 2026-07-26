package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/TexHik620953/liberator-node-go/internal/appconfig"
	"github.com/TexHik620953/liberator-node-go/internal/infra/ipapi"

	"github.com/TexHik620953/liberator-node-go/internal/utils/cert"
	"github.com/TexHik620953/liberator-node-go/internal/utils/safemap"
	"github.com/TexHik620953/liberator-node-go/pkg/firewall"
	"github.com/TexHik620953/liberator-node-go/pkg/iface"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh"
	"github.com/TexHik620953/liberator-node-go/pkg/router"
	"github.com/TexHik620953/liberator-node-go/pkg/routingtable"
	"github.com/TexHik620953/liberator-node-go/pkg/services/firewallmanager"
	"github.com/TexHik620953/liberator-node-go/pkg/services/peersmanager"
	"github.com/TexHik620953/liberator-node-go/pkg/transport"
	"github.com/TexHik620953/liberator-node-go/pkg/transport/awg"

	_ "github.com/mattn/go-sqlite3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	grpcctrl "github.com/TexHik620953/liberator-node-go/pkg/api/controllers/grpc"
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

	// Certs
	nodeCert tls.Certificate
	rootPool *x509.CertPool

	ipInfo *ipapi.IpInfo
}

func New(ctx context.Context, cfg *appconfig.AppConfig) (*App, error) {
	app := &App{
		ctx:          ctx,
		cfg:          cfg,
		routingTable: routingtable.New(),
		firewall:     firewall.New(),
		transports:   safemap.New[string, transport.Transport](),
		rootPool:     x509.NewCertPool(),
	}
	var err error
	// Load certs
	rootCa, err := cert.ReadCertificateFromFile(cfg.Auth.RootCert)
	if err != nil {
		return nil, fmt.Errorf("failed to load root cert: %v", err)
	}

	app.rootPool.AddCert(rootCa)

	app.nodeCert, err = tls.LoadX509KeyPair(cfg.Auth.Cert, cfg.Auth.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to load node cert: %v", err)
	}

	// Grpc listener and server
	app.grpcLis, err = net.Listen("tcp", cfg.Api.Grpc.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to launch grpc server: %w", err)
	}

	app.grpcServer = grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{app.nodeCert},
		NextProtos:   []string{"nodectl"},
	})))

	// Db
	if app.db, err = sql.Open("sqlite3", app.cfg.Database.File); err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}
	if err = app.db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %v", err)
	}
	err = app.migrateDatabase()
	if err != nil {
		return nil, fmt.Errorf("failed to migrate database: %v", err)
	}

	// managers
	app.firewallManager = firewallmanager.New(app.ctx, app.firewall, app.db)
	app.peersManager = peersmanager.New(app.ctx, app.db, app.firewallManager, app.cfg.Router.CIDR)

	// Network stuff
	if app.router, err = router.New(ctx, cfg.Router, app.routingTable, app.firewall); err != nil {
		return nil, fmt.Errorf("failed to create router: %v", err)
	}

	if app.node, err = mesh.New(ctx, cfg.Mesh, app.nodeCert, app.rootPool, app.router); err != nil {
		return nil, fmt.Errorf("failed to create mesh node: %v", err)
	}

	// Get current server ip and location
	ipInfo, err := ipapi.GetIpInfo()
	if err != nil {
		log.Printf("failed to update err: %v", err)
		ipInfo = &ipapi.IpInfo{
			CountryCode: "UNKNOWN",
		}
	}
	app.ipInfo = ipInfo

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
	grpcctrl.RegisterNodeService(app.grpcServer, app.node.NodeID(), *app.ipInfo, app.transports)

	if err := app.firewallManager.Run(); err != nil {
		return fmt.Errorf("failed to start firewall manager: %v", err)
	}
	if err := app.peersManager.Run(); err != nil {
		return fmt.Errorf("failed to start peers manager: %v", err)
	}

	var wg sync.WaitGroup
	wg.Go(app.router.Run)
	wg.Go(app.node.Run)
	wg.Go(app.tunIface.Run)

	app.transports.Foreach(func(_ string, t transport.Transport) {
		wg.Go(t.Run)
	})

	go func() {
		if err := app.grpcServer.Serve(app.grpcLis); err != nil {
			log.Fatalf("failed to start grpc server: %v", err)
		}
	}()

	wg.Wait()
	app.grpcServer.Stop()
	app.grpcLis.Close()

	return nil
}
