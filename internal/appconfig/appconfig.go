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

// ClientConfig — желаемый клиент, приходящий из state API.
type ClientConfig struct {
	VirtualIP      uint32   `yaml:"virtual_ip"`
	AwgPublicKey   string   `yaml:"awg_public_key"`
	TrafficLimitGb *float64 `yaml:"traffic_limit_gb"`
	SpeedLimitMbps *float64 `yaml:"speed_limit_mbps"`
}

// VPNConfig — bootstrap overlay-настройки до первого state от API.
type VPNConfig struct {
	GlobalCIDR  string `yaml:"global_cidr"`
	GatewayAddr string `yaml:"gateway_addr"`
}

// MeshConfig - пул QUIC-подключений к остальным нодам. Ноды узнаются не через
// gossip-дискавери, а из статического списка и/или k8s-DNS (headless-сервис).
type MeshConfig struct {
	ListenAddr string   `yaml:"listen_addr"` // UDP/quic listen ноды
	DNSService string   `yaml:"dns_service"` // headless-сервис k8s -> IP нод
	DNSPort    int      `yaml:"dns_port"`    // quic-порт остальных нод
	Static     []string `yaml:"static"`      // запасной список "host:port" для dev
}

// ServerConfig - TCP-listen ноды для /healthz и /metrics (нода без control-plane).
type ServerConfig struct {
	ListenAddr string `yaml:"listen_addr"`
}

// APIConfig - настройки восходящего API, к которому нода ходит сама (пассивная).
type APIConfig struct {
	BaseURL           string        `yaml:"base_url"` // напр. http://liberator-api:8080
	RegionCode        string        `yaml:"region_code"`
	PublicEndpoint    string        `yaml:"public_endpoint"` // куда клиентам подключаться (host:port)
	MeshEndpoint      string        `yaml:"mesh_endpoint"`   // QUIC endpoint ноды (host:port) для форвардинга
	SyncInterval      time.Duration `yaml:"sync_interval"`
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
}

// AppConfig общая структура конфигурации
type AppConfig struct {
	Auth        AuthConfig   `yaml:"auth"`
	TunConfig   TUNConfig    `yaml:"tun"`
	Router      RouterConfig `yaml:"router"`
	VPN         VPNConfig    `yaml:"vpn"`
	Mesh        MeshConfig   `yaml:"mesh"`
	Server      ServerConfig `yaml:"server"`
	API         APIConfig    `yaml:"api"`
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
