package appconfig

import (
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

// AuthConfig содержит настройки аутентификации (общий secret для control-plane
// и для QUIC-пула между нодами). Сертификаты убраны.
type AuthConfig struct {
	Secret string `yaml:"secret_key"`
}

// TUNConfig настройки выхода в интернет
type TUNConfig struct {
	IfaceInName  string `yaml:"iface_in_name"`
	IfaceOutName string `yaml:"iface_out_name"`
	MTU          int    `yaml:"mtu"`
}

// RouterConfig
type RouterConfig struct {
	Transports map[string]map[string]any `yaml:"transports"`
}

// RuleConfig - правило файрвола для клиента.
type RuleConfig struct {
	TargetAddress  *uint32 `yaml:"target_ip"`
	Protocol       string  `yaml:"protocol"`
	PortRangeStart uint16  `yaml:"port_range_start"`
	PortRangeEnd   *uint16 `yaml:"port_range_end"`
}

// ClientConfig - желаемое состояние клиента (config-фид; позже из API).
type ClientConfig struct {
	VirtualIP      uint32       `yaml:"virtual_ip"`
	AwgPublicKey   string       `yaml:"awg_public_key"`
	Expiration     *time.Time   `yaml:"expiration"`
	TrafficLimitGb *float64     `yaml:"traffic_limit_gb"`
	SpeedLimitMbps *float64     `yaml:"speed_limit_mbps"`
	Rules          []RuleConfig `yaml:"rules"`
}

// VPNConfig - распределённая виртуальная сеть, которую создают ноды.
// Пока приходит из конфига (config-фид); в дальнейшем замещается state из API.
type VPNConfig struct {
	GlobalCIDR  string         `yaml:"global_cidr"`  // общий для всех нод overlay-диапазон
	GatewayAddr string         `yaml:"gateway_addr"` // overlay IP этой ноды (одна из global_cidr)
	Clients     []ClientConfig `yaml:"clients"`      // желаемые клиенты (временный фид)
}

// MeshConfig - пул QUIC-подключений к остальным нодам. Ноды узнаются не через
// gossip-дискавери, а из статического списка и/или k8s-DNS (headless-сервис).
type MeshConfig struct {
	ListenAddr string   `yaml:"listen_addr"` // UDP/quic listen ноды
	DNSService string   `yaml:"dns_service"` // headless-сервис k8s -> IP нод
	DNSPort    int      `yaml:"dns_port"`    // quic-порт остальных нод
	Static     []string `yaml:"static"`      // запасной список "host:port" для dev
}

type GrpcConfig struct {
	ListenAddr string `yaml:"listen_addr"`
}

type HttpConfig struct {
	ListenAddr string `yaml:"listen_addr"`
}
type ApiConfig struct {
	Grpc GrpcConfig `yaml:"grpc"`
	Http HttpConfig `yaml:"http"`
}

// AppConfig общая структура конфигурации
type AppConfig struct {
	Auth        AuthConfig   `yaml:"auth"`
	TunConfig   TUNConfig    `yaml:"tun"`
	Router      RouterConfig `yaml:"router"`
	VPN         VPNConfig    `yaml:"vpn"`
	Mesh        MeshConfig   `yaml:"mesh"`
	Api         ApiConfig    `yaml:"api"`
	CountryCode string       `yaml:"country_code"`
}

// LoadAppConfig загружает конфигурацию из YAML-файла
func LoadAppConfig(configFile string) (*AppConfig, error) {
	var cfg AppConfig
	if err := cleanenv.ReadConfig(configFile, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
