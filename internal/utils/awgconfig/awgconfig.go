package awgconfig

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/google/uuid"
)

// ClientParams параметры для генерации
type ClientParams struct {
	ServerAddr   string
	ServerPort   int
	ServerPubKey string
	ServerPSK    string // Опционально: PresharedKey

	ClientPrivKey string
	ClientPubKey  string
	ClientIP      string // Формат "10.8.0.2/32"
	DNSServer     string

	// Параметры обфускации передаем строками, чтобы поддержать любой формат
	H1, H2, H3, H4     string
	I1, I2, I3, I4, I5 string // Опционально
	Jc, Jmin, Jmax     string
	S1, S2, S3, S4     string
}

// --- Внутренние структуры для парсинга в JSON ---

type rootConfig struct {
	Containers       []container `json:"containers"`
	DefaultContainer string      `json:"defaultContainer"`
	Description      string      `json:"description"`
	Dns1             string      `json:"dns1"`
	Dns2             string      `json:"dns2"`
	HostName         string      `json:"hostName"`
}

type container struct {
	Container string    `json:"container"` // ДОЛЖНО БЫТЬ "amnezia-awg2"
	Awg       awgConfig `json:"awg"`
}

type awgConfig struct {
	H1              string `json:"H1"`
	H2              string `json:"H2"`
	H3              string `json:"H3"`
	H4              string `json:"H4"`
	I1              string `json:"I1,omitempty"`
	I2              string `json:"I2,omitempty"`
	I3              string `json:"I3,omitempty"`
	I4              string `json:"I4,omitempty"`
	I5              string `json:"I5,omitempty"`
	Jc              string `json:"Jc"`
	Jmax            string `json:"Jmax"`
	Jmin            string `json:"Jmin"`
	S1              string `json:"S1"`
	S2              string `json:"S2"`
	S3              string `json:"S3,omitempty"`
	S4              string `json:"S4,omitempty"`
	LastConfig      string `json:"last_config"` // ЗДЕСЬ ЛЕЖИТ СТРОКА С ВЛОЖЕННЫМ JSON!
	Port            string `json:"port"`
	ProtocolVersion string `json:"protocol_version"`
	SubnetAddress   string `json:"subnet_address"`
	TransportProto  string `json:"transport_proto"`
}

// lastConfigInner это то, что лежит внутри поля last_config в виде строки
type lastConfigInner struct {
	H1                  string   `json:"H1"`
	H2                  string   `json:"H2"`
	H3                  string   `json:"H3"`
	H4                  string   `json:"H4"`
	Jc                  string   `json:"Jc"`
	Jmin                string   `json:"Jmin"`
	Jmax                string   `json:"Jmax"`
	S1                  string   `json:"S1"`
	S2                  string   `json:"S2"`
	AllowedIPs          []string `json:"allowed_ips"`
	ClientId            string   `json:"clientId"`
	ClientIP            string   `json:"client_ip"`
	ClientPrivKey       string   `json:"client_priv_key"`
	ClientPubKey        string   `json:"client_pub_key"`
	Config              string   `json:"config"`
	HostName            string   `json:"hostName"`
	Mtu                 string   `json:"mtu"`
	PersistentKeepAlive string   `json:"persistent_keep_alive"`
	Port                string   `json:"port"`
	PskKey              string   `json:"psk_key,omitempty"`
	ServerPubKey        string   `json:"server_pub_key"`
}

// GenerateURI собирает ссылку vpn:// в формате Amnezia v2
func GenerateURI(p *ClientParams) (string, string, error) {
	// 1. Генерируем обычный INI текст (как фоллбэк для клиента)
	iniStr := buildINIString(p)

	// 2. Вычисляем subnet_address (берем сеть из IP клиента)
	_, ipNet, err := net.ParseCIDR(p.ClientIP)
	subnet := "10.0.0.0"
	if err == nil {
		subnet = ipNet.IP.String()
	}

	// Генерируем случайный clientId (Base64 от UUID)
	clientId := base64.StdEncoding.EncodeToString([]byte(uuid.New().String()))

	serverPubB64 := hexToBase64(p.ServerPubKey)
	clientPrivB64 := hexToBase64(p.ClientPrivKey)
	clientPubB64 := hexToBase64(p.ClientPubKey) // клиенту нужен и его публичный ключ

	// 3. Формируем внутренний объект last_config
	lastCfg := lastConfigInner{
		H1: p.H1, H2: p.H2, H3: p.H3, H4: p.H4,
		Jc: p.Jc, Jmin: p.Jmin, Jmax: p.Jmax, S1: p.S1, S2: p.S2,
		AllowedIPs:          []string{"0.0.0.0/0", "::/0"},
		ClientId:            clientId,
		ClientIP:            strings.Replace(p.ClientIP, "/32", "", 1),
		ClientPrivKey:       clientPrivB64,
		ClientPubKey:        clientPubB64,
		Config:              iniStr,
		HostName:            p.ServerAddr,
		Mtu:                 "1350",
		PersistentKeepAlive: "25",
		Port:                fmt.Sprintf("%d", p.ServerPort),
		PskKey:              p.ServerPSK,
		ServerPubKey:        serverPubB64,
	}

	// Сериализуем last_config в JSON СТРОКУ (ключевой момент!)
	lastCfgBytes, err := json.Marshal(lastCfg)
	if err != nil {
		return "", "", err
	}

	// 4. Формируем основной JSON объект
	root := rootConfig{
		Containers: []container{
			{
				Container: "amnezia-awg2", // Строго этот контейнер
				Awg: awgConfig{
					H1: p.H1, H2: p.H2, H3: p.H3, H4: p.H4,
					I1: p.I1, I2: p.I2, I3: p.I3, I4: p.I4, I5: p.I5,
					Jc: p.Jc, Jmin: p.Jmin, Jmax: p.Jmax,
					S1: p.S1, S2: p.S2, S3: p.S3, S4: p.S4,
					LastConfig:      string(lastCfgBytes), // Вставляем строку
					Port:            fmt.Sprintf("%d", p.ServerPort),
					ProtocolVersion: "2",
					SubnetAddress:   subnet,
					TransportProto:  "udp",
				},
			},
		},
		DefaultContainer: "amnezia-awg2",
		Description:      "Liberator Node",
		Dns1:             p.DNSServer,
		Dns2:             "",
		HostName:         p.ServerAddr,
	}

	// Сериализуем весь корень в JSON
	rootJsonBytes, err := json.Marshal(root)
	if err != nil {
		return "", "", err
	}

	// 5. Сжимаем Zlib
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	w.Write(rootJsonBytes)
	w.Close()
	compressedBytes := buf.Bytes()

	// 6. Формируем 4-байтовый заголовок (размер оригинального JSON)
	size := len(rootJsonBytes)
	header := []byte{
		byte(size >> 24),
		byte(size >> 16),
		byte(size >> 8),
		byte(size),
	}

	// Склеиваем и кодируем
	finalBytes := append(header, compressedBytes...)
	encodedStr := base64.RawURLEncoding.EncodeToString(finalBytes)

	return "vpn://" + encodedStr, iniStr, nil
}

// Вспомогательная функция генерации INI текста (для поля Config внутри last_config)
func buildINIString(p *ClientParams) string {
	var sb strings.Builder

	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("Address = %s\n", p.ClientIP))
	sb.WriteString(fmt.Sprintf("DNS = %s\n", p.DNSServer))
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", p.ClientPrivKey))

	if p.Jc != "" {
		sb.WriteString(fmt.Sprintf("Jc = %s\n", p.Jc))
		sb.WriteString(fmt.Sprintf("Jmin = %s\n", p.Jmin))
		sb.WriteString(fmt.Sprintf("Jmax = %s\n", p.Jmax))
		sb.WriteString(fmt.Sprintf("S1 = %s\n", p.S1))
		sb.WriteString(fmt.Sprintf("S2 = %s\n", p.S2))
	}

	sb.WriteString(fmt.Sprintf("H1 = %s\n", p.H1))
	sb.WriteString(fmt.Sprintf("H2 = %s\n", p.H2))
	sb.WriteString(fmt.Sprintf("H3 = %s\n", p.H3))
	sb.WriteString(fmt.Sprintf("H4 = %s\n", p.H4))

	if p.I1 != "" {
		sb.WriteString(fmt.Sprintf("I1 = %s\n", p.I1))
	}
	if p.I2 != "" {
		sb.WriteString(fmt.Sprintf("I2 = %s\n", p.I2))
	}
	if p.I3 != "" {
		sb.WriteString(fmt.Sprintf("I3 = %s\n", p.I3))
	}
	if p.I4 != "" {
		sb.WriteString(fmt.Sprintf("I4 = %s\n", p.I4))
	}
	if p.I5 != "" {
		sb.WriteString(fmt.Sprintf("I5 = %s\n", p.I5))
	}

	sb.WriteString("\n[Peer]\n")
	sb.WriteString(fmt.Sprintf("PublicKey = %s\n", p.ServerPubKey))
	if p.ServerPSK != "" {
		sb.WriteString(fmt.Sprintf("PresharedKey = %s\n", p.ServerPSK))
	}
	sb.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")
	sb.WriteString(fmt.Sprintf("Endpoint = %s:%d\n", p.ServerAddr, p.ServerPort))
	sb.WriteString("PersistentKeepalive = 25\n")

	return sb.String()
}

func hexToBase64(h string) string {
	b, _ := hex.DecodeString(h)
	return base64.StdEncoding.EncodeToString(b)
}
