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

	"github.com/liberator-vpn/liberator-node-go/internal/appconfig"
)

func TestEnsureIdentityEnrollsThenLoadsFromDisk(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/node/enroll" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		calls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"node_id": "node-1", "secret": "secret-1",
			"gateway_addr": "100.64.0.2", "global_cidr": "100.64.0.0/10",
		})
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

	// Второй вызов должен прочитать файл и не ходить в API.
	if _, err := app.ensureIdentity(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("enroll calls = %d, want 1", calls.Load())
	}
}
