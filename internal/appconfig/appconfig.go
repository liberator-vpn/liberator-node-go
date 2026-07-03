package appconfig

import (
	"github.com/ilyakaznacheev/cleanenv"
)

// AuthConfig содержит настройки аутентификации
type AuthConfig struct {
	JWTSecret string `yaml:"jwt_secret"`
	RootCA    string `yaml:"root_ca"`
}

// EgressConfig настройки выхода в интернет
type EgressConfig struct {
	IfaceInName  string `yaml:"iface_in_name"`
	IfaceOutName string `yaml:"iface_out_name"`
}

// IngressConfig настройки входящих QUIC-соединений
type IngressConfig struct {
	ListenAddr string `yaml:"listen_addr"`
	Cert       string `yaml:"cert"`
}

// BridgeConfig связывает ingress и egress, задаёт подсеть
type BridgeConfig struct {
	Ingress string `yaml:"ingress"`
	Egress  string `yaml:"egress"`
	CIDR    string `yaml:"cidr"`
	MTU     int    `yaml:"mtu"`
	DNS     string `yaml:"dns"`
}

// MeshConfig для кластеризации (обнаружение пиров)
type MeshConfig struct {
	ListenAddr        string   `yaml:"listen_addr"`
	BootstrapAddr     []string `yaml:"bootstrap_addr"`
	PeersStore        string   `yaml:"peers_store"`
	DiscoveryInterval string   `yaml:"discovery_interval"`
	RTTUpdateInterval string   `yaml:"rtt_update_interval"`
}

// MetricsConfig для сбора метрик
type MetricsConfig struct {
	ListenAddr string `yaml:"listen_addr"`
}

// AppConfig общая структура конфигурации
type AppConfig struct {
	Auth    AuthConfig               `yaml:"auth"`
	Egress  map[string]EgressConfig  `yaml:"egress"`
	Ingress map[string]IngressConfig `yaml:"ingress"`
	Bridge  map[string]BridgeConfig  `yaml:"bridge"`
	Mesh    MeshConfig               `yaml:"mesh"`
	Metrics MetricsConfig            `yaml:"metrics"`
}

// LoadAppConfig загружает конфигурацию из YAML-файла
func LoadAppConfig(configFile string) (*AppConfig, error) {
	var cfg AppConfig
	if err := cleanenv.ReadConfig(configFile, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
