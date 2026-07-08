package main

import (
	"context"
	"liberator-node-go/internal/app"
	"liberator-node-go/internal/appconfig"
	"log"

	// _ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	/*
		runtime.SetMutexProfileFraction(1)
		runtime.SetBlockProfileRate(1)
		go func() {
			http.ListenAndServe(":80", nil)
		}()
	*/
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

	application.Run()

	<-ctx.Done()
}
