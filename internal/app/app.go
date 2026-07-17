package app

import (
	"context"
	"fmt"
	"liberator-node-go/internal/appconfig"
	"liberator-node-go/internal/infra/repos"

	"liberator-node-go/internal/utils/routingtable"
	"liberator-node-go/pkg/bridge"
	"liberator-node-go/pkg/mesh"
	"liberator-node-go/pkg/services/liberatorjwt"
)

type App struct {
	ctx context.Context
	cfg *appconfig.AppConfig

	jwtIss *liberatorjwt.LiberatorJWT

	bridge *bridge.Bridge
	node   *mesh.MeshNode

	repo *repos.DbPool

	routingTable routingtable.RoutingTable
}

func New(ctx context.Context, cfg *appconfig.AppConfig) (*App, error) {
	app := &App{
		ctx:          ctx,
		cfg:          cfg,
		jwtIss:       liberatorjwt.New([]byte(cfg.Auth.JWTSecret)),
		routingTable: routingtable.New(),
	}
	var err error

	// Create repos
	app.repo, err = repos.NewDbPool(cfg.Database)
	if err != nil {
		return nil, fmt.Errorf("failed to create database: %v", err)
	}

	// Create service

	// Create mesh node
	app.node, err = mesh.New(ctx, cfg.Mesh, app.routingTable)
	if err != nil {
		return nil, fmt.Errorf("failed to create mesh node: %v", err)
	}

	// Create bridges
	bridge, err := bridge.New(ctx, cfg.Bridge, app.node, app.routingTable)
	if err != nil {
		return nil, fmt.Errorf("failed to build bridge: %v", err)
	}
	app.bridge = bridge
	return app, nil
}

func (app *App) Run() {
	go app.bridge.Run()
	go app.node.Run()
}
