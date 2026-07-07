package appconfig

import (
	"github.com/ilyakaznacheev/cleanenv"
)

// AuthConfig содержит настройки аутентификации
type AuthConfig struct {
	JWTSecret string `yaml:"jwt_secret"`
	RootCA    string `yaml:"root_ca"`
}

// IngressConfig настройки входящих QUIC-соединений
type IngressConfig struct {
	Type       string `yaml:"type"`
	ListenAddr string `yaml:"listen_addr"`
	Cert       string `yaml:"cert"`
	Key        string `yaml:"key"`
}

// EgressConfig настройки выхода в интернет
type EgressConfig struct {
	IfaceInName  string `yaml:"iface_in_name"`
	IfaceOutName string `yaml:"iface_out_name"`
}

// BridgeConfig описывает один мост (bridge) со своим ingress/egress и сетевой конфигурацией
type BridgeConfig struct {
	Ingresses map[string]IngressConfig `yaml:"ingresses"`
	Egress    EgressConfig             `yaml:"egress"`
	CIDR      string                   `yaml:"cidr"`
	MTU       int                      `yaml:"mtu"`
	DNS       string                   `yaml:"dns"`
}

// MeshConfig для кластеризации (обнаружение пиров)
type MeshConfig struct {
	ListenAddr        string   `yaml:"listen_addr"`
	BootstrapAddr     []string `yaml:"bootstrap_addr"`
	PeersStore        string   `yaml:"peers_store"`
	DiscoveryInterval string   `yaml:"discovery_interval"`  // можно заменить на time.Duration
	RTTUpdateInterval string   `yaml:"rtt_update_interval"` // можно заменить на time.Duration
}

// MetricsConfig для сбора метрик
type MetricsConfig struct {
	ListenAddr string `yaml:"listen_addr"`
}

// AppConfig общая структура конфигурации
type AppConfig struct {
	Auth    AuthConfig              `yaml:"auth"`
	Bridge  map[string]BridgeConfig `yaml:"bridge"` // ключ — имя моста
	Mesh    MeshConfig              `yaml:"mesh"`
	Metrics MetricsConfig           `yaml:"metrics"`
}

// LoadAppConfig загружает конфигурацию из YAML-файла
func LoadAppConfig(configFile string) (*AppConfig, error) {
	var cfg AppConfig
	if err := cleanenv.ReadConfig(configFile, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
