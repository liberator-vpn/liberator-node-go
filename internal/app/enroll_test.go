package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/liberator-vpn/liberator-node-go/internal/apiclient"
	"github.com/liberator-vpn/liberator-node-go/internal/appconfig"
)

func TestEnsureIdentityEnrollsThenLoadsFromDisk(t *testing.T) {
	var enrollCalls, whoamiCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/node/enroll":
			enrollCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"node_id": "node-1", "secret": "secret-1",
				"gateway_addr": "100.64.0.2", "global_cidr": "100.64.0.0/10",
			})
		case "/v1/node/whoami":
			whoamiCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"node_id": "node-1", "gateway_addr": "100.64.0.2"})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	app := &App{cfg: &appconfig.AppConfig{API: appconfig.APIConfig{
		BaseURL: srv.URL, EnrollmentToken: "tok", RegionCode: "de",
		PublicEndpoint: "127.0.0.1:2200", MeshEndpoint: "127.0.0.1:9000",
		NodeName: "n1", StateDir: dir,
	}}}
	id, err := app.ensureIdentity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if id.NodeID != "node-1" || id.Secret != "secret-1" {
		t.Fatalf("unexpected identity: %+v", id)
	}
	path := filepath.Join(dir, "node-identity.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("identity not saved: %v", err)
	}

	// Второй вызов проверяет identity через whoami и не делает enroll.
	if _, err := app.ensureIdentity(context.Background()); err != nil {
		t.Fatal(err)
	}
	if enrollCalls.Load() != 1 || whoamiCalls.Load() != 1 {
		t.Fatalf("enroll calls = %d, whoami calls = %d", enrollCalls.Load(), whoamiCalls.Load())
	}
}

func TestEnsureIdentityReenrollsWhenStoredSecretRejected(t *testing.T) {
	var enrollCalls, whoamiCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/node/whoami":
			whoamiCalls.Add(1)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"code":"unauthorized"}}`))
		case "/v1/node/enroll":
			enrollCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"node_id": "node-1", "secret": "secret-new",
				"gateway_addr": "100.64.0.2", "global_cidr": "100.64.0.0/10",
			})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "node-identity.json")
	if err := apiclient.SaveIdentity(path, &apiclient.Identity{
		NodeID: "node-1", Secret: "secret-old", GatewayAddr: "100.64.0.2",
	}); err != nil {
		t.Fatal(err)
	}

	app := &App{cfg: &appconfig.AppConfig{API: appconfig.APIConfig{
		BaseURL: srv.URL, EnrollmentToken: "tok", RegionCode: "de",
		PublicEndpoint: "127.0.0.1:2200", MeshEndpoint: "127.0.0.1:9000",
		NodeName: "n1", StateDir: dir,
	}}}
	id, err := app.ensureIdentity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if id.Secret != "secret-new" {
		t.Fatalf("expected re-enrolled secret, got %+v", id)
	}
	if enrollCalls.Load() != 1 || whoamiCalls.Load() != 1 {
		t.Fatalf("enroll calls = %d, whoami calls = %d", enrollCalls.Load(), whoamiCalls.Load())
	}
	saved, err := apiclient.LoadIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Secret != "secret-new" {
		t.Fatalf("identity not updated: %+v", saved)
	}
}

func TestEnsureIdentityKeepsIdentityWhenAPIUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "node-identity.json")
	if err := apiclient.SaveIdentity(path, &apiclient.Identity{
		NodeID: "node-1", Secret: "secret-1", GatewayAddr: "100.64.0.2",
	}); err != nil {
		t.Fatal(err)
	}
	app := &App{cfg: &appconfig.AppConfig{API: appconfig.APIConfig{
		BaseURL: srv.URL, EnrollmentToken: "tok", NodeName: "n1", StateDir: dir,
	}}}
	id, err := app.ensureIdentity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if id.Secret != "secret-1" {
		t.Fatalf("stored identity must be kept on API 5xx, got %+v", id)
	}
}
