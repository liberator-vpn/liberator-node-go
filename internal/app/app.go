package app

import (
	"context"
	"fmt"
	"liberator-node-go/internal/appconfig"
	"liberator-node-go/internal/utils/liberatorjwt"
	"liberator-node-go/internal/utils/safemap"
	"liberator-node-go/pkg/bridge"
)

type App struct {
	ctx context.Context
	cfg *appconfig.AppConfig

	jwtIss  *liberatorjwt.LiberatorJWT
	bridges safemap.Safemap[string, *bridge.Bridge]
}

func New(ctx context.Context, cfg *appconfig.AppConfig) (*App, error) {
	app := &App{
		ctx:     ctx,
		cfg:     cfg,
		bridges: safemap.New[string, *bridge.Bridge](),
		jwtIss:  liberatorjwt.New([]byte(cfg.Auth.JWTSecret)),
	}

	// Create bridges
	for name, bconf := range cfg.Bridge {
		if app.bridges.Exists(name) {
			return nil, fmt.Errorf("duplicated bridge name: %s", name)
		}

		bridge, err := bridge.New(ctx, bconf, app.jwtIss)
		if err != nil {
			return nil, fmt.Errorf("failed to build bridge %s: %v", name, err)
		}
		app.bridges.Set(name, bridge)
	}

	return app, nil
}

func (app *App) Run() {
	app.bridges.Foreach(func(s string, b *bridge.Bridge) {
		go b.Run()
	})
}
