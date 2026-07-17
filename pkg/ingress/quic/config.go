package ingressquic

import "gopkg.in/yaml.v3"

// IngressConfig настройки входящих QUIC-соединений
type IngressConfig struct {
	MTU        int    `yaml:"mtu"`
	ListenAddr string `yaml:"listen_addr"`
	Cert       string `yaml:"cert"`
	Key        string `yaml:"key"`
}

func ParseConfig(config any) (*IngressConfig, error) {
	var ing IngressConfig
	data, err := yaml.Marshal(config)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(data, &ing); err != nil {
		return nil, err
	}
	return &ing, nil
}
