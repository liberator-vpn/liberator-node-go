package apiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"
)

// Live-тест контракта с запущенным liberator-api.
//
//	LIBERATOR_API_TEST_URL=http://127.0.0.1:18080 \
//	LIBERATOR_API_TEST_ADMIN_KEY=... \
//	go test ./internal/apiclient -run TestLiveNodeContract -v
func TestLiveNodeContract(t *testing.T) {
	base := os.Getenv("LIBERATOR_API_TEST_URL")
	admin := os.Getenv("LIBERATOR_API_TEST_ADMIN_KEY")
	if base == "" || admin == "" {
		t.Skip("set LIBERATOR_API_TEST_URL and LIBERATOR_API_TEST_ADMIN_KEY")
	}
	ctx := context.Background()

	token, err := createEnrollmentToken(ctx, base, admin)
	if err != nil {
		t.Fatal(err)
	}
	suffix := time.Now().UnixNano()
	name := fmt.Sprintf("live-node-%d", suffix)
	anon := New(base, "")
	en, err := anon.Enroll(ctx, EnrollRequest{
		Token: token, Name: name, Hostname: name,
		PublicEndpoint: "127.0.0.1:2200", MeshEndpoint: "127.0.0.1:9000",
		RegionCode: "test", AgentVersion: "test",
		Protocols: []Protocol{{Protocol: "amnesiav2", Capacity: 10}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		req, _ := http.NewRequest(http.MethodDelete, base+"/v1/admin/cluster/nodes/"+en.NodeID, nil)
		req.Header.Set("X-Admin-Key", admin)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
	})

	c := New(base, en.Secret)
	if err := c.Heartbeat(ctx, en.NodeID, Heartbeat{ActiveSessions: 0, LoadPercent: 1, AgentVersion: "test"}); err != nil {
		t.Fatal(err)
	}
	st, err := c.GetState(ctx, en.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if st.NodeID != en.NodeID || st.Status != "active" {
		t.Fatalf("unexpected state: %+v", st)
	}
	if _, err := c.GetClients(ctx, en.NodeID); err != nil {
		t.Fatal(err)
	}
}

func createEnrollmentToken(ctx context.Context, base, admin string) (string, error) {
	body, _ := json.Marshal(map[string]string{"ttl": "5m"})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/admin/cluster/enrollment-tokens", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Admin-Key", admin)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("create token: %s", resp.Status)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.Token, nil
}
