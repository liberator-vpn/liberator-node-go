package awg

import (
	"time"

	"gopkg.in/yaml.v3"
)

// Protocol — имя туннельного протокола (AmneziaWG) для метрик.
const Protocol = "amneziawg"

// TransportConfig настройки входящих AmneziaWG-соединений
type TransportConfig struct {
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
	return &ing, nil
}
