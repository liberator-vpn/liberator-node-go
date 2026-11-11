package xray

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func testPrivateKey() string {
	priv := make([]byte, 32)
	for i := range priv {
		priv[i] = byte(i + 1)
	}
	return base64.RawURLEncoding.EncodeToString(priv)
}

func baseConfig() *TransportConfig {
	return &TransportConfig{
		Inbounds: []InboundConfig{
			{
				Protocol:    ProtocolVLESS,
				Port:        443,
				Dest:        "www.microsoft.com:443",
				PrivateKey:  testPrivateKey(),
				ServerNames: []string{"www.microsoft.com"},
				ShortIDs:    []string{"0123456789abcdef"},
			},
			{
				Protocol: ProtocolHysteria2,
				Port:     8443,
				CertFile: "/certs/fullchain.pem",
				KeyFile:  "/certs/key.pem",
				SNI:      "vpn.example.com",
			},
		},
		Users: []UserConfig{
			{Name: "alice@liberator", Auth: "11111111-1111-1111-1111-111111111111", Protocol: ProtocolVLESS, VirtualIP: "100.64.0.10"},
			{Name: "bob@liberator", Auth: "bob-password", Protocol: ProtocolHysteria2, VirtualIP: "100.64.0.11"},
		},
	}
}

func TestBuildConfigContainsPerUserSendThroughAndRouting(t *testing.T) {
	cfg := baseConfig()
	if err := cfg.normalize(); err != nil {
		t.Fatal(err)
	}
	data, err := cfg.BuildConfig(cfg.Users)
	if err != nil {
		t.Fatal(err)
	}

	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	outbounds := root["outbounds"].([]any)
	foundAlice := false
	for _, o := range outbounds {
		ob := o.(map[string]any)
		if ob["tag"] == "user-100_64_0_10" {
			foundAlice = true
			if ob["sendThrough"] != "100.64.0.10" {
				t.Fatalf("sendThrough = %v", ob["sendThrough"])
			}
		}
	}
	if !foundAlice {
		t.Fatal("alice outbound with sendThrough not found")
	}

	routing := root["routing"].(map[string]any)
	rules := routing["rules"].([]any)
	foundRule := false
	for _, r := range rules {
		rule := r.(map[string]any)
		if rule["outboundTag"] == "user-100_64_0_10" {
			foundRule = true
		}
	}
	if !foundRule {
		t.Fatal("alice routing rule not found")
	}
}

func TestBuildConfigIncludesBothInbounds(t *testing.T) {
	cfg := baseConfig()
	if err := cfg.normalize(); err != nil {
		t.Fatal(err)
	}
	data, err := cfg.BuildConfig(cfg.Users)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	_ = json.Unmarshal(data, &root)
	inbounds := root["inbounds"].([]any)
	if len(inbounds) != 2 {
		t.Fatalf("inbounds = %d, want 2", len(inbounds))
	}
	if !strings.Contains(string(data), `"protocol": "hysteria"`) {
		t.Fatal("hysteria inbound missing")
	}
	if !strings.Contains(string(data), `"realitySettings"`) {
		t.Fatal("reality settings missing")
	}
}

func TestNormalizeRejectsInvalidConfig(t *testing.T) {
	cfg := baseConfig()
	cfg.Inbounds[0].PrivateKey = ""
	if err := cfg.normalize(); err == nil {
		t.Fatal("missing vless private key must be rejected")
	}

	cfg = baseConfig()
	cfg.Users[0].Protocol = "vless"
	cfg.Users[0].VirtualIP = "not-an-ip"
	if err := cfg.normalize(); err == nil {
		t.Fatal("invalid virtual_ip must be rejected")
	}

	// При двух inbound протокол пользователя обязателен: иначе непонятно,
	// в какой inbound его добавлять.
	cfg = baseConfig()
	cfg.Users[0].Protocol = ""
	if err := cfg.normalize(); err == nil {
		t.Fatal("protocol must be required when multiple inbounds are configured")
	}

	// При одном inbound протокол можно не указывать.
	cfg = baseConfig()
	cfg.Inbounds = cfg.Inbounds[:1]
	cfg.Users = cfg.Users[:1]
	cfg.Users[0].Protocol = ""
	if err := cfg.normalize(); err != nil {
		t.Fatalf("explicit protocol not required when one inbound: %v", err)
	}
}

func TestClientURIs(t *testing.T) {
	cfg := baseConfig()
	if err := cfg.normalize(); err != nil {
		t.Fatal(err)
	}
	vless, err := cfg.ClientURI(cfg.Users[0], "203.0.113.10:443", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(vless, "vless://11111111-1111-1111-1111-111111111111@203.0.113.10:443?") {
		t.Fatalf("unexpected vless URI: %s", vless)
	}
	if !strings.Contains(vless, "security=reality") || !strings.Contains(vless, "pbk=") {
		t.Fatalf("vless URI lacks reality params: %s", vless)
	}

	hy2, err := cfg.ClientURI(cfg.Users[1], "203.0.113.10:8443", "bob")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hy2, "hysteria2://bob-password@203.0.113.10:8443/") {
		t.Fatalf("unexpected hysteria2 URI: %s", hy2)
	}
}
