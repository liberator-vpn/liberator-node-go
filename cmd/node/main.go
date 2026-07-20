package main

import (
	"context"
	"log"

	"github.com/TexHik620953/liberator-node-go/internal/app"
	"github.com/TexHik620953/liberator-node-go/internal/appconfig"

	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if len(os.Args) < 2 {
		log.Printf("pass config like ./liberator-node ./config.yaml")
		return
	}

	cfg, err := appconfig.LoadAppConfig(os.Args[1])
	if err != nil {
		log.Panicf("failed to load config: %v", err)
	}

	application, err := app.New(ctx, cfg)
	if err != nil {
		log.Panicf("failed to create application: %v", err)
	}

	err = application.Run()
	if err != nil {
		log.Fatalf("failed to run app: %v", err)
	}
}
