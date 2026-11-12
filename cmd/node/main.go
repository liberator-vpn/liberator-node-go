package main

import (
	"context"
	"log"

	"github.com/liberator-vpn/liberator-node-go/internal/app"
	"github.com/liberator-vpn/liberator-node-go/internal/appconfig"

	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if len(os.Args) < 2 {
		// Не return: контейнер без аргумента должен падать, а не выглядеть
		// здоровым (readiness/liveness на /healthz при этом не поднимался).
		log.Fatal("pass config like ./liberator-node ./config.yaml")
	}

	cfg, err := appconfig.LoadAppConfig(os.Args[1])
	if err != nil {
		log.Panicf("failed to load config: %v", err)
	}

	// Общий флот-секрет можно задать из env (k8s Secret), не держа его в config-файле.
	if v := os.Getenv("LIBERATOR_NODE_SHARED_SECRET"); v != "" {
		cfg.Auth.Secret = v
	}
	// Enrollment-токен — секрет, поэтому его можно передать через env/Secret.
	// Остальные параметры (state_dir, identity_file, node_name, agent_version)
	// задаются в config.yaml.
	if v := os.Getenv("LIBERATOR_NODE_ENROLLMENT_TOKEN"); v != "" {
		cfg.API.EnrollmentToken = v
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
