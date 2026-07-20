package app

import (
	"context"
	"database/sql"
	"fmt"
	"liberator-node-go/internal/appconfig"
	"log"
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
}

func New(ctx context.Context, cfg *appconfig.AppConfig) (*App, error) {
	app := &App{
		ctx:          ctx,
		cfg:          cfg,
		routingTable: routingtable.New(),
		firewall:     firewall.New(),
		transports:   safemap.New[string, transport.Transport](),
	}
	var err error

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

			app.testCreateUser(icfg, trp)
		default:
			return nil, fmt.Errorf("unknown ingress type: %s", typ)
		}
		app.transports.Set(name, trp)
		app.peersManager.RegisterTransport(name, trp)
	}
	return app, nil
}

func (app *App) testCreateUser(icfg *awg.TransportConfig, trp transport.Transport) {

	serverPubKey, err := getServerPubKey(icfg.PrivateKey)
	if err != nil {
		log.Fatalf("Failed to calc server pub key: %v", err)
	}
	fmt.Printf("Сервер Public Key (HEX): %s\n", serverPubKey)

	//clientPrivKey := "58627383123294ebb76f5831ddcf3d40ed31104a9ef1c1accaf007efb4318b73"
	//clientPubKey := "afa89c215becc53d4bc90562b7e1c8667298ec39ff3cff47857052c55a45b402"
	// Генерируем ключи клиента СРАЗУ В HEX
	//clientPrivKey, clientPubKey, err := generateKeyPair()
	//if err != nil {
	//	log.Fatalf("Failed to generate client keys: %v", err)
	//}
	/*
		err = trp.PreparePeer(netutils.IPStringToUint32(clientIp), clientPubKey, 0)
		if err != nil {
			log.Fatalf("Failed to prepare peer: %v", err)
		}

		clientTestConfig, _, err := awgconfig.GenerateURI(&awgconfig.ClientParams{
			ServerAddr:    "192.168.68.121",
			ServerPort:    2200,
			ServerPubKey:  serverPubKey,
			ClientPrivKey: clientPrivKey,
			ClientIP:      clientIp + "/32",
			DNSServer:     "10.0.0.1",

			// Передаем ОБЯЗАТЕЛЬНО строками!
			H1:   icfg.H1,
			H2:   icfg.H2,
			H3:   icfg.H3,
			H4:   icfg.H4,
			Jc:   strconv.Itoa(icfg.Jc),
			Jmin: strconv.Itoa(icfg.JMin),
			Jmax: strconv.Itoa(icfg.JMax),
			S1:   strconv.Itoa(icfg.S1),
			S2:   strconv.Itoa(icfg.S2),
		})
		if err != nil {
			log.Fatalf("Failed to gen config: %v", err)
		}
				fmt.Println(clientTestConfig)
	*/
}

func (app *App) Run() error {
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

	wg.Wait()

	return nil
}
