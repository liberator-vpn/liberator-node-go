package xray

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/crypto/curve25519"
	"gopkg.in/yaml.v3"
)

const (
	ProtocolVLESS     = "vless"
	ProtocolHysteria2 = "hysteria2"
)

// InboundConfig описывает один клиентский inbound Xray.
type InboundConfig struct {
	// Protocol: "vless" (VLESS+REALITY) или "hysteria2".
	Protocol string `yaml:"protocol"`
	Listen   string `yaml:"listen"`
	Port     int    `yaml:"port"`

	// VLESS + REALITY.
	Flow        string   `yaml:"flow"` // обычно xtls-rprx-vision
	Dest        string   `yaml:"dest"` // host:port для REALITY handshake
	PrivateKey  string   `yaml:"private_key"`
	ServerNames []string `yaml:"server_names"`
	ShortIDs    []string `yaml:"short_ids"`

	// Hysteria2 TLS.
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	SNI      string `yaml:"sni"`
}

// UserConfig — статический пользователь, заданный в конфиге ноды. Так как
// control-plane пока не умеет выдавать proxy-сессии, это основной способ
// завести VLESS/Hysteria2-пользователей.
type UserConfig struct {
	Name      string `yaml:"name"`
	Auth      string `yaml:"auth"` // UUID для VLESS, пароль для Hysteria2
	VirtualIP string `yaml:"virtual_ip"`
	Protocol  string `yaml:"protocol"` // vless | hysteria2; пусто = единственный inbound
	Flow      string `yaml:"flow"`

	// SendThrough — локальный source-IP, который назначает нода. В конфиге
	// не задаётся; заполняется транспортом из local_cidr.
	SendThrough string `yaml:"-"`
}

type TransportConfig struct {
	Binary string `yaml:"binary"`
	MTU    int    `yaml:"mtu"`

	// ProxyTUN — TUN, в который Xray отправляет расшифрованный трафик.
	// Dummy — dummy-интерфейс, на котором живут local_ip пользователей.
	ProxyTUN string `yaml:"proxy_tun"`
	Dummy    string `yaml:"dummy"`

	// StateDir/ConfigPath: куда писать конфиг Xray. Если ConfigPath пуст,
	// используется <state_dir>/xray.json; если StateDir пуст — временный каталог.
	StateDir   string `yaml:"state_dir"`
	ConfigPath string `yaml:"config_path"`

	// Policy routing: таблицы/приоритеты для source-based маршрутизации
	// local_ip -> proxy_tun. Диапазон должен быть свободен на хосте.
	RouteTableBase   int `yaml:"route_table_base"`
	RulePriorityBase int `yaml:"rule_priority_base"`

	// LocalCIDR — пул локальных source-IP для Xray (назначаются на dummy).
	// Не должен пересекаться с overlay и реальными сетями.
	LocalCIDR string `yaml:"local_cidr"`

	Inbounds []InboundConfig `yaml:"inbounds"`
	Users    []UserConfig    `yaml:"users"`
}

func ParseConfig(config any) (*TransportConfig, error) {
	var out TransportConfig
	data, err := yaml.Marshal(config)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	if err := out.normalize(); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *TransportConfig) normalize() error {
	if c.Binary == "" {
		c.Binary = "xray"
	}
	if c.MTU <= 0 {
		c.MTU = 1376
	}
	if c.ProxyTUN == "" {
		c.ProxyTUN = "liberator-proxy"
	}
	if c.Dummy == "" {
		c.Dummy = "liberator-proxy-dummy"
	}
	if c.RouteTableBase <= 0 {
		c.RouteTableBase = 20000
	}
	if c.RulePriorityBase <= 0 {
		c.RulePriorityBase = 20000
	}
	if c.LocalCIDR == "" {
		c.LocalCIDR = "198.18.0.0/15"
	}
	if _, _, err := net.ParseCIDR(c.LocalCIDR); err != nil {
		return fmt.Errorf("xray: invalid local_cidr %q: %w", c.LocalCIDR, err)
	}
	if len(c.Inbounds) == 0 {
		return fmt.Errorf("xray: at least one inbound is required")
	}

	seenPorts := make(map[string]struct{})
	for i := range c.Inbounds {
		ib := &c.Inbounds[i]
		if ib.Listen == "" {
			ib.Listen = "0.0.0.0"
		}
		if ib.Port <= 0 || ib.Port > 65535 {
			return fmt.Errorf("xray: inbound %d has invalid port", i)
		}
		if _, ok := seenPorts[ib.Protocol+":"+strconv.Itoa(ib.Port)]; ok {
			return fmt.Errorf("xray: duplicate inbound %s port %d", ib.Protocol, ib.Port)
		}
		seenPorts[ib.Protocol+":"+strconv.Itoa(ib.Port)] = struct{}{}

		switch ib.Protocol {
		case ProtocolVLESS:
			if ib.Dest == "" {
				return fmt.Errorf("xray: vless inbound requires dest")
			}
			if ib.PrivateKey == "" {
				return fmt.Errorf("xray: vless inbound requires private_key")
			}
			if len(ib.ServerNames) == 0 {
				return fmt.Errorf("xray: vless inbound requires server_names")
			}
			if ib.Flow == "" {
				ib.Flow = "xtls-rprx-vision"
			}
			if len(ib.ShortIDs) == 0 {
				ib.ShortIDs = []string{""}
			}
		case ProtocolHysteria2:
			if ib.CertFile == "" || ib.KeyFile == "" {
				return fmt.Errorf("xray: hysteria2 inbound requires cert_file and key_file")
			}
		default:
			return fmt.Errorf("xray: unsupported inbound protocol %q", ib.Protocol)
		}
	}

	inboundProtocols := c.inboundProtocols()
	for i := range c.Users {
		u := &c.Users[i]
		if u.Name == "" {
			return fmt.Errorf("xray: user %d has empty name", i)
		}
		if u.VirtualIP == "" || net.ParseIP(u.VirtualIP) == nil {
			return fmt.Errorf("xray: user %q has invalid virtual_ip", u.Name)
		}
		if u.Protocol == "" {
			if len(inboundProtocols) != 1 {
				return fmt.Errorf("xray: user %q must set protocol when multiple inbounds are configured", u.Name)
			}
			u.Protocol = inboundProtocols[0]
		}
		if !contains(inboundProtocols, u.Protocol) {
			return fmt.Errorf("xray: user %q references unknown inbound protocol %q", u.Name, u.Protocol)
		}
	}
	return nil
}

func (c *TransportConfig) inboundProtocols() []string {
	seen := make(map[string]struct{}, len(c.Inbounds))
	out := make([]string, 0, len(c.Inbounds))
	for _, ib := range c.Inbounds {
		if _, ok := seen[ib.Protocol]; ok {
			continue
		}
		seen[ib.Protocol] = struct{}{}
		out = append(out, ib.Protocol)
	}
	return out
}

func (c *TransportConfig) Protocols() []string { return c.inboundProtocols() }

func (c *TransportConfig) inbound(protocol string) (InboundConfig, bool) {
	for _, ib := range c.Inbounds {
		if ib.Protocol == protocol {
			return ib, true
		}
	}
	return InboundConfig{}, false
}

// BuildConfig собирает JSON-конфиг Xray для набора пользователей.
// Каждый пользователь получает свой freedom-outbound с sendThrough=virtual_ip,
// поэтому пакеты попадают в proxy-TUN уже с правильным source IP и дальше
// идут через общий роутер ноды.
func (c *TransportConfig) BuildConfig(users []UserConfig) ([]byte, error) {
	if err := c.normalize(); err != nil {
		return nil, err
	}

	inbounds := make([]any, 0, len(c.Inbounds))
	for _, ib := range c.Inbounds {
		switch ib.Protocol {
		case ProtocolVLESS:
			clients := make([]any, 0)
			for _, u := range users {
				if u.Protocol != ProtocolVLESS {
					continue
				}
				flow := u.Flow
				if flow == "" {
					flow = ib.Flow
				}
				clients = append(clients, map[string]any{
					"id": u.Auth, "email": u.Name, "flow": flow,
				})
			}
			inbounds = append(inbounds, map[string]any{
				"tag":      "vless-reality",
				"listen":   ib.Listen,
				"port":     ib.Port,
				"protocol": "vless",
				"settings": map[string]any{
					"clients":    clients,
					"decryption": "none",
				},
				"streamSettings": map[string]any{
					"network":  "tcp",
					"security": "reality",
					"realitySettings": map[string]any{
						"show":        false,
						"dest":        ib.Dest,
						"xver":        0,
						"serverNames": ib.ServerNames,
						"privateKey":  ib.PrivateKey,
						"shortIds":    ib.ShortIDs,
					},
				},
			})
		case ProtocolHysteria2:
			hUsers := make([]any, 0)
			for _, u := range users {
				if u.Protocol != ProtocolHysteria2 {
					continue
				}
				hUsers = append(hUsers, map[string]any{"auth": u.Auth, "email": u.Name})
			}
			inbounds = append(inbounds, map[string]any{
				"tag":      "hysteria2",
				"listen":   ib.Listen,
				"port":     ib.Port,
				"protocol": "hysteria",
				"settings": map[string]any{
					"version": 2,
					"users":   hUsers,
				},
				"streamSettings": map[string]any{
					"network":  "hysteria",
					"security": "tls",
					"tlsSettings": map[string]any{
						"alpn": []string{"h3"},
						"certificates": []any{map[string]any{
							"certificateFile": ib.CertFile,
							"keyFile":         ib.KeyFile,
						}},
					},
					"hysteriaSettings": map[string]any{"version": 2},
				},
			})
		}
	}

	outbounds := make([]any, 0, len(users)+1)
	rules := make([]any, 0, len(users))
	for _, u := range users {
		tag := userTag(u.VirtualIP)
		sendThrough := u.SendThrough
		if sendThrough == "" {
			sendThrough = u.VirtualIP
		}
		outbounds = append(outbounds, map[string]any{
			"tag":         tag,
			"protocol":    "freedom",
			"sendThrough": sendThrough,
			"settings":    map[string]any{},
			"streamSettings": map[string]any{
				"sockopt": map[string]any{"domainStrategy": "UseIP"},
			},
		})
		rules = append(rules, map[string]any{
			"type":        "field",
			"user":        []string{u.Name},
			"outboundTag": tag,
		})
	}
	// Первый outbound — fallback для запросов без совпавшего user.
	outbounds = append(outbounds, map[string]any{
		"tag":      "direct",
		"protocol": "freedom",
		"settings": map[string]any{},
		"streamSettings": map[string]any{
			"sockopt": map[string]any{"domainStrategy": "UseIP"},
		},
	})

	root := map[string]any{
		"log":       map[string]any{"loglevel": "warning"},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing": map[string]any{
			"domainStrategy": "AsIs",
			"rules":          rules,
		},
	}
	return json.MarshalIndent(root, "", "  ")
}

func userTag(vip string) string {
	return "user-" + strings.NewReplacer(".", "_", ":", "_").Replace(vip)
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// ClientURI собирает ссылку для ручного подключения клиента. API пока не
// умеет отдавать proxy-конфиги, поэтому URI полезен для статических users.
func (c *TransportConfig) ClientURI(u UserConfig, addr, name string) (string, error) {
	ib, ok := c.inbound(u.Protocol)
	if !ok {
		return "", fmt.Errorf("xray: no inbound for protocol %q", u.Protocol)
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if name == "" {
		name = u.Name
	}

	switch u.Protocol {
	case ProtocolVLESS:
		pub, err := realityPublicKey(ib.PrivateKey)
		if err != nil {
			return "", err
		}
		sni := ""
		if len(ib.ServerNames) > 0 {
			sni = ib.ServerNames[0]
		}
		sid := ""
		if len(ib.ShortIDs) > 0 {
			sid = ib.ShortIDs[0]
		}
		flow := u.Flow
		if flow == "" {
			flow = ib.Flow
		}
		q := url.Values{}
		q.Set("encryption", "none")
		q.Set("flow", flow)
		q.Set("security", "reality")
		q.Set("sni", sni)
		q.Set("fp", "chrome")
		q.Set("pbk", pub)
		q.Set("sid", sid)
		q.Set("type", "tcp")
		link := &url.URL{
			Scheme:   "vless",
			User:     url.User(u.Auth),
			Host:     net.JoinHostPort(host, strconv.Itoa(ib.Port)),
			RawQuery: q.Encode(),
			Fragment: name,
		}
		return link.String(), nil
	case ProtocolHysteria2:
		sni := ib.SNI
		if sni == "" {
			sni = host
		}
		q := url.Values{}
		q.Set("sni", sni)
		q.Set("insecure", "0")
		link := &url.URL{
			Scheme:   "hysteria2",
			User:     url.User(u.Auth),
			Host:     net.JoinHostPort(host, strconv.Itoa(ib.Port)),
			Path:     "/",
			RawQuery: q.Encode(),
			Fragment: name,
		}
		return link.String(), nil
	default:
		return "", fmt.Errorf("xray: unsupported protocol %q", u.Protocol)
	}
}

// RealityPublicKey выводит публичный ключ REALITY из приватного (base64url).
func RealityPublicKey(private string) (string, error) { return realityPublicKey(private) }

// realityPublicKey выводит публичный ключ REALITY из приватного (base64url).
func realityPublicKey(private string) (string, error) {
	priv, err := decodeBase64URL(private)
	if err != nil {
		return "", fmt.Errorf("xray: invalid reality private key: %w", err)
	}
	if len(priv) != 32 {
		return "", fmt.Errorf("xray: reality private key must be 32 bytes")
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(pub), nil
}

func decodeBase64URL(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}
