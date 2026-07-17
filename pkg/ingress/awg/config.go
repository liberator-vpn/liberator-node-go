package awg

import "gopkg.in/yaml.v3"

// IngressConfig настройки входящих AmneziaWG-соединений
type IngressConfig struct {
	MTU        int    `yaml:"mtu"`
	ListenAddr string `yaml:"listen_addr"`
	PrivateKey string `yaml:"private_key"`

	// Принимаем именно строки диапазонов!
	H1 string `yaml:"h1"`
	H2 string `yaml:"h2"`
	H3 string `yaml:"h3"`
	H4 string `yaml:"h4"`

	Jc   int `yaml:"jc"`
	JMin int `yaml:"jmin"`
	JMax int `yaml:"jmax"`
	S1   int `yaml:"s1"`
	S2   int `yaml:"s2"`
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
