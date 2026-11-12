package awg

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	ProtocolAmneziaV2  = "amnesiav2"
	ProtocolAmneziaV31 = "amnesiav31"
)

// TransportConfig настройки входящих AmneziaWG-соединений.
type TransportConfig struct {
	// Protocol: amnesiav2 (AWG 2.x) или amnesiav31 (AWG 3.1).
	// Пусто = amnesiav2.
	Protocol string `yaml:"protocol"`

	MTU              int           `yaml:"mtu"`
	ListenPort       int           `yaml:"listen_port"`
	PrivateKey       string        `yaml:"private_key"`
	WatchdogInterval time.Duration `yaml:"watchdog_interval"`

	// Принимаем именно строки диапазонов!
	H1 string `yaml:"h1"`
	H2 string `yaml:"h2"`
	H3 string `yaml:"h3"`
	H4 string `yaml:"h4"`

	// I1..I5 — опциональные «signature»/padding-пакеты AmneziaWG 1.5+/2.0.
	I1 string `yaml:"i1"`
	I2 string `yaml:"i2"`
	I3 string `yaml:"i3"`
	I4 string `yaml:"i4"`
	I5 string `yaml:"i5"`

	Jc   int `yaml:"jc"`
	JMin int `yaml:"jmin"`
	JMax int `yaml:"jmax"`
	S1   int `yaml:"s1"`
	S2   int `yaml:"s2"`
	S3   int `yaml:"s3"`
	S4   int `yaml:"s4"`

	// AWG 3.1. HeaderProtectionKey хранится в base64 (как в клиентском
	// конфиге/URI); в UAPI уходит hex.
	HeaderProtectionKey    string `yaml:"header_protection_key"`
	ContentPaddingAddition string `yaml:"content_padding_addition"`
	RekeyAfterTime         string `yaml:"rekey_after_time"`
	RekeyTimeout           string `yaml:"rekey_timeout"`
	RejectAfterTime        string `yaml:"reject_after_time"`
	KeepaliveTimeout       string `yaml:"keepalive_timeout"`
	MaxHandshakeAttempts   string `yaml:"max_handshake_attempts"`
	RandomTrailers         bool   `yaml:"random_trailers"`
	DisableCookies         bool   `yaml:"disable_cookies"`
}

func ParseConfig(config any) (*TransportConfig, error) {
	var ing TransportConfig
	data, err := yaml.Marshal(config)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(data, &ing); err != nil {
		return nil, err
	}
	if err := ing.normalize(); err != nil {
		return nil, err
	}
	return &ing, nil
}

func (c *TransportConfig) normalize() error {
	c.Protocol = NormalizeProtocol(c.Protocol)
	if !IsAWGProtocol(c.Protocol) {
		return fmt.Errorf("awg: unsupported protocol %q", c.Protocol)
	}
	if c.Protocol == ProtocolAmneziaV31 && c.HeaderProtectionKey == "" {
		return fmt.Errorf("awg: %s requires header_protection_key", ProtocolAmneziaV31)
	}
	if c.HeaderProtectionKey != "" {
		raw, err := decodeHeaderKey(c.HeaderProtectionKey)
		if err != nil {
			return fmt.Errorf("awg: invalid header_protection_key: %w", err)
		}
		if len(raw) != 32 {
			return fmt.Errorf("awg: header_protection_key must be 32 bytes")
		}
		if c.S1 < 12 || c.S2 < 12 || c.S3 < 12 || c.S4 < 12 {
			return fmt.Errorf("awg: header protection requires s1..s4 >= 12")
		}
	}
	for name, val := range map[string]string{
		"content_padding_addition": c.ContentPaddingAddition,
		"rekey_after_time":         c.RekeyAfterTime,
		"rekey_timeout":            c.RekeyTimeout,
		"reject_after_time":        c.RejectAfterTime,
		"keepalive_timeout":        c.KeepaliveTimeout,
		"max_handshake_attempts":   c.MaxHandshakeAttempts,
	} {
		if val == "" {
			continue
		}
		if err := validateUintRange(val); err != nil {
			return fmt.Errorf("awg: invalid %s %q: %w", name, val, err)
		}
	}
	return nil
}

func NormalizeProtocol(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "", "awg", "amneziawg", ProtocolAmneziaV2:
		return ProtocolAmneziaV2
	case ProtocolAmneziaV31:
		return ProtocolAmneziaV31
	default:
		return p
	}
}

func IsAWGProtocol(p string) bool {
	p = NormalizeProtocol(p)
	return p == ProtocolAmneziaV2 || p == ProtocolAmneziaV31
}

func (c *TransportConfig) headerKeyHex() (string, error) {
	raw, err := decodeHeaderKey(c.HeaderProtectionKey)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func decodeHeaderKey(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("not valid base64")
}

func validateUintRange(s string) error {
	parts := strings.Split(s, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return fmt.Errorf("expected a or a-b")
	}
	lo, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 32)
	if err != nil {
		return err
	}
	if len(parts) == 2 {
		hi, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 32)
		if err != nil {
			return err
		}
		if hi < lo {
			return fmt.Errorf("range end is less than start")
		}
	}
	return nil
}
