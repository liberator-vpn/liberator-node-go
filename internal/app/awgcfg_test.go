package app

import (
	"encoding/base64"
	"testing"

	"github.com/liberator-vpn/liberator-node-go/internal/appconfig"
)

func TestBuildCapabilitiesIncludesProxyProtocols(t *testing.T) {
	priv := make([]byte, 32)
	for i := range priv {
		priv[i] = byte(i + 1)
	}
	cfg := &appconfig.AppConfig{
		Router: appconfig.RouterConfig{Transports: map[string]map[string]any{
			"edge": {
				"type": "xray",
				"inbounds": []any{
					map[string]any{
						"protocol":     "vless",
						"port":         443,
						"dest":         "www.microsoft.com:443",
						"private_key":  base64.RawURLEncoding.EncodeToString(priv),
						"server_names": []any{"www.microsoft.com"},
						"short_ids":    []any{"0123456789abcdef"},
					},
					map[string]any{
						"protocol":  "hysteria2",
						"port":      8443,
						"cert_file": "/certs/fullchain.pem",
						"key_file":  "/certs/key.pem",
						"sni":       "vpn.example.com",
					},
				},
			},
		}},
	}

	caps := buildCapabilities(cfg)
	if caps == nil {
		t.Fatal("capabilities are nil")
	}
	if _, ok := caps["vless"]; !ok {
		t.Fatal("vless capabilities missing")
	}
	if _, ok := caps["hysteria2"]; !ok {
		t.Fatal("hysteria2 capabilities missing")
	}
}
