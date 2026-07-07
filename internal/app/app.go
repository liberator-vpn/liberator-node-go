package app

import (
	"context"
	"fmt"
	"liberator-node-go/internal/appconfig"
	"liberator-node-go/internal/infra/repos"
	"liberator-node-go/internal/utils/liberatorjwt"
	"liberator-node-go/internal/utils/safemap"
	"liberator-node-go/pkg/bridge"
	"liberator-node-go/pkg/mesh"
)

type App struct {
	ctx context.Context
	cfg *appconfig.AppConfig

	jwtIss  *liberatorjwt.LiberatorJWT
	bridges safemap.Safemap[string, *bridge.Bridge]
	node    *mesh.MeshNode

	repo *repos.DbPool
}

func New(ctx context.Context, cfg *appconfig.AppConfig) (*App, error) {
	app := &App{
		ctx:     ctx,
		cfg:     cfg,
		bridges: safemap.New[string, *bridge.Bridge](),
		jwtIss:  liberatorjwt.New([]byte(cfg.Auth.JWTSecret)),
	}
	var err error

	// Create repos
	app.repo, err = repos.NewDbPool(cfg.Database)
	if err != nil {
		return nil, fmt.Errorf("failed to create database: %v", err)
	}

	// Create mesh node
	app.node, err = mesh.New(ctx, cfg.Mesh)
	if err != nil {
		return nil, fmt.Errorf("failed to create mesh node: %v", err)
	}

	// Create bridges
	for name, bconf := range cfg.Bridge {
		if app.bridges.Exists(name) {
			return nil, fmt.Errorf("duplicated bridge name: %s", name)
		}

		bridge, err := bridge.New(ctx, bconf, app.jwtIss, app.node, app.repo)
		if err != nil {
			return nil, fmt.Errorf("failed to build bridge %s: %v", name, err)
		}
		app.bridges.Set(name, bridge)
	}

	users, err := app.repo.Query().ListUsers(ctx)
	if err != nil {
		panic(err)
	}
	for _, u := range users {
		token, _ := app.jwtIss.SignToken(u.ID)
		fmt.Printf("[%s]: %s\n", u.Login, token)
	}

	return app, nil
}

func (app *App) Run() {
	app.bridges.Foreach(func(s string, b *bridge.Bridge) {
		go b.Run()
	})
	go app.node.Run()
}
