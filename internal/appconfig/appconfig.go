package appconfig

import (
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

// AuthConfig содержит настройки аутентификации
type AuthConfig struct {
	JWTSecret string `yaml:"jwt_secret"`
}

// TUNConfig настройки выхода в интернет
type TUNConfig struct {
	IfaceInName  string `yaml:"iface_in_name"`
	IfaceOutName string `yaml:"iface_out_name"`
	MTU          int    `yaml:"mtu"`
}

// RouterConfig описывает один мост (bridge) со своим ingress/egress и сетевой конфигурацией
type RouterConfig struct {
	Transports map[string]map[string]any `yaml:"transports"`
	GlobalCIRD string                    `yaml:"global_cidr"`
	CIDR       string                    `yaml:"cidr"`
}

// MeshConfig для кластеризации (обнаружение пиров)
type MeshConfig struct {
	ListenAddr        string        `yaml:"listen_addr"`
	BootstrapAddrs    []string      `yaml:"bootstrap_addrs"`
	PeersStore        string        `yaml:"peers_store"`
	DiscoveryInterval time.Duration `yaml:"discovery_interval"`
	RTTUpdateInterval time.Duration `yaml:"rtt_update_interval"`
	Cert              string        `yaml:"cert"`
	Key               string        `yaml:"key"`
	RootCert          string        `yaml:"root_cert"`
}

// MetricsConfig для сбора метрик
type MetricsConfig struct {
	ListenAddr string `yaml:"listen_addr"`
}

// DatabaseConfig - бд
type DatabaseConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	Database string `yaml:"database"`
}

// AppConfig общая структура конфигурации
type AppConfig struct {
	Auth      AuthConfig     `yaml:"auth"`
	TunConfig TUNConfig      `yaml:"tun"`
	Router    RouterConfig   `yaml:"router"`
	Mesh      MeshConfig     `yaml:"mesh"`
	Database  DatabaseConfig `yaml:"database"`
	Metrics   MetricsConfig  `yaml:"metrics"`
}

// LoadAppConfig загружает конфигурацию из YAML-файла
func LoadAppConfig(configFile string) (*AppConfig, error) {
	var cfg AppConfig
	if err := cleanenv.ReadConfig(configFile, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
