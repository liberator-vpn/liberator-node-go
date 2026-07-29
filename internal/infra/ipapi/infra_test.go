package ipapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetIP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","countryCode":"FI"}`))
	}))
	defer server.Close()

	info, err := getIpInfo(context.Background(), server.Client(), server.URL)
	if err != nil {
		t.Fatalf("get IP info: %v", err)
	}
	if info.CountryCode != "FI" {
		t.Fatalf("country code: got %q, want FI", info.CountryCode)
	}
}
