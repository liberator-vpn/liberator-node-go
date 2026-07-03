package app

import (
	"context"
	"liberator-node-go/internal/appconfig"
	"liberator-node-go/pkg/egress"
	"liberator-node-go/pkg/ingress"
)

type App struct {
	ctx context.Context
	cfg *appconfig.AppConfig

	ingresses map[string]*ingress.Ingress
	egresses  map[string]*egress.Egress
}

func New(ctx context.Context, cfg *appconfig.AppConfig) (*App, error) {
	app := &App{
		ctx: ctx,
		cfg: cfg,
	}

	return app, nil
}
