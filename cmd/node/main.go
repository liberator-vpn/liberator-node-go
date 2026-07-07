package main

import (
	"context"
	"liberator-node-go/internal/app"
	"liberator-node-go/internal/appconfig"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg, err := appconfig.LoadAppConfig("./config.yaml")
	if err != nil {
		panic(err)
	}

	application, err := app.New(ctx, cfg)
	if err != nil {
		panic(err)
	}

	application.Run()

	<-ctx.Done()
}
