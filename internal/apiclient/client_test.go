package apiclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestEnrollHeartbeatStatePaths(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/v1/node/enroll":
			if r.Header.Get("Authorization") != "" {
				t.Errorf("enroll must not send node bearer")
			}
			_ = json.NewEncoder(w).Encode(EnrollResult{
				NodeID: "node-1", Secret: "secret-1", GatewayAddr: "100.64.0.1", GlobalCIDR: "100.64.0.0/10",
			})
		case "/v1/node/heartbeat":
			if r.Header.Get("X-Node-Id") != "node-1" || r.Header.Get("Authorization") != "Bearer secret-1" {
				t.Errorf("bad node auth headers: %v", r.Header)
			}
			w.WriteHeader(http.StatusOK)
		case "/v1/node/state":
			if r.Header.Get("X-Node-Id") != "node-1" {
				t.Errorf("missing node id")
			}
			_, _ = w.Write([]byte(`{"node_id":"node-1","status":"active","sessions":[]}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	ctx := context.Background()
	anon := New(srv.URL, "")
	en, err := anon.Enroll(ctx, EnrollRequest{Token: "tok", Name: "n1", Hostname: "n1", PublicEndpoint: "1.2.3.4:2200", RegionCode: "de"})
	if err != nil {
		t.Fatal(err)
	}
	if en.NodeID != "node-1" || en.Secret != "secret-1" {
		t.Fatalf("unexpected enroll result: %+v", en)
	}

	c := New(srv.URL, en.Secret)
	if err := c.Heartbeat(ctx, en.NodeID, Heartbeat{ActiveSessions: 1}); err != nil {
		t.Fatal(err)
	}
	st, err := c.GetState(ctx, en.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if st.NodeID != "node-1" || st.Status != "active" {
		t.Fatalf("unexpected state: %+v", st)
	}
	want := []string{"POST /v1/node/enroll", "POST /v1/node/heartbeat", "GET /v1/node/state"}
	if len(got) != len(want) {
		t.Fatalf("paths = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("paths = %v, want %v", got, want)
		}
	}
}

func TestIdentityRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node-identity.json")
	in := &Identity{NodeID: "n1", Secret: "s1", GatewayAddr: "100.64.0.1", GlobalCIDR: "100.64.0.0/10"}
	if err := SaveIdentity(path, in); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("identity mode = %v, want 0600", info.Mode().Perm())
	}
	out, err := LoadIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if out == nil || *out != *in {
		t.Fatalf("identity round trip mismatch: %+v", out)
	}
}
