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

func TestBuildCapabilitiesIncludesAWGVersions(t *testing.T) {
	priv := make([]byte, 32)
	for i := range priv {
		priv[i] = byte(i + 1)
	}
	header := make([]byte, 32)
	for i := range header {
		header[i] = byte(100 + i)
	}
	cfg := &appconfig.AppConfig{
		Router: appconfig.RouterConfig{Transports: map[string]map[string]any{
			"amnesiav2": {
				"type": "awg", "protocol": "amnesiav2", "mtu": 1376,
				"listen_port": 2200, "private_key": hexKey(priv),
				"h1": "1-2", "h2": "3-4", "h3": "5-6", "h4": "7-8",
				"jc": 5, "jmin": 70, "jmax": 120, "s1": 48, "s2": 27, "s3": 30, "s4": 7,
			},
			"amnesiav31": {
				"type": "awg", "protocol": "amnesiav31", "mtu": 1376,
				"listen_port": 2201, "private_key": hexKey(priv),
				"h1": "1-2", "h2": "3-4", "h3": "5-6", "h4": "7-8",
				"jc": 5, "jmin": 70, "jmax": 120, "s1": 48, "s2": 27, "s3": 30, "s4": 13,
				"header_protection_key":    base64.StdEncoding.EncodeToString(header),
				"content_padding_addition": "0-32",
				"rekey_after_time":         "120-180",
				"random_trailers":          true,
			},
		}},
	}
	caps := buildCapabilities(cfg)
	v2, ok := caps["amnesiav2"].(map[string]any)
	if !ok {
		t.Fatalf("amnesiav2 capabilities missing: %#v", caps)
	}
	if _, ok := v2["header_protection_key"]; ok {
		t.Fatal("v2 must not advertise header protection")
	}
	v31, ok := caps["amnesiav31"].(map[string]any)
	if !ok {
		t.Fatalf("amnesiav31 capabilities missing: %#v", caps)
	}
	if v31["header_protection_key"] == "" || v31["random_trailers"] != true {
		t.Fatalf("v31 fields missing: %#v", v31)
	}
	protocols := buildProtocols(cfg)
	seen := map[string]bool{}
	for _, p := range protocols {
		seen[p.Protocol] = true
	}
	if !seen["amnesiav2"] || !seen["amnesiav31"] {
		t.Fatalf("protocols = %#v", protocols)
	}
}

func hexKey(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0x0f]
	}
	return string(out)
}
