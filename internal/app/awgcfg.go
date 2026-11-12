package app

import (
	"fmt"

	"github.com/liberator-vpn/liberator-node-go/internal/apiclient"
	"github.com/liberator-vpn/liberator-node-go/internal/appconfig"
	"github.com/liberator-vpn/liberator-node-go/pkg/transport/awg"
	"github.com/liberator-vpn/liberator-node-go/pkg/transport/xray"
)

// buildCapabilities собирает параметры входов ноды для регистрации в API.
// AWG-транспорты публикуются под своими именами: amnesiav2 / amnesiav31.
func buildCapabilities(cfg *appconfig.AppConfig) map[string]any {
	out := make(map[string]any)

	for _, iconf := range cfg.Router.Transports {
		typ, _ := iconf["type"].(string)
		switch typ {
		case "awg":
			icfg, err := awg.ParseConfig(iconf)
			if err != nil {
				continue
			}
			pub, err := awg.ServerPublicKey(icfg.PrivateKey)
			if err != nil {
				continue
			}
			awgParams := map[string]any{
				"server_public_key": pub,
				"mtu":               icfg.MTU,
				"listen_port":       icfg.ListenPort,
				"jc":                icfg.Jc,
				"jmin":              icfg.JMin,
				"jmax":              icfg.JMax,
				"s1":                icfg.S1,
				"s2":                icfg.S2,
				"s3":                icfg.S3,
				"s4":                icfg.S4,
				"h1":                icfg.H1,
				"h2":                icfg.H2,
				"h3":                icfg.H3,
				"h4":                icfg.H4,
			}
			// I1..I5 — только непустые: клиент не должен получать пустые
			// signature-пакеты, если нода работает в режиме AWG 1.0.
			for i, val := range []string{icfg.I1, icfg.I2, icfg.I3, icfg.I4, icfg.I5} {
				if val != "" {
					awgParams[fmt.Sprintf("i%d", i+1)] = val
				}
			}
			if icfg.HeaderProtectionKey != "" {
				awgParams["header_protection_key"] = icfg.HeaderProtectionKey
			}
			if icfg.ContentPaddingAddition != "" {
				awgParams["content_padding_addition"] = icfg.ContentPaddingAddition
			}
			if icfg.RekeyAfterTime != "" {
				awgParams["rekey_after_time"] = icfg.RekeyAfterTime
			}
			if icfg.RekeyTimeout != "" {
				awgParams["rekey_timeout"] = icfg.RekeyTimeout
			}
			if icfg.RejectAfterTime != "" {
				awgParams["reject_after_time"] = icfg.RejectAfterTime
			}
			if icfg.KeepaliveTimeout != "" {
				awgParams["keepalive_timeout"] = icfg.KeepaliveTimeout
			}
			if icfg.MaxHandshakeAttempts != "" {
				awgParams["max_handshake_attempts"] = icfg.MaxHandshakeAttempts
			}
			if icfg.RandomTrailers {
				awgParams["random_trailers"] = true
			}
			if icfg.DisableCookies {
				awgParams["disable_cookies"] = true
			}
			out[icfg.Protocol] = awgParams
		case "xray":
			icfg, err := xray.ParseConfig(iconf)
			if err != nil {
				continue
			}
			for _, ib := range icfg.Inbounds {
				switch ib.Protocol {
				case xray.ProtocolVLESS:
					pub, err := xray.RealityPublicKey(ib.PrivateKey)
					if err != nil {
						continue
					}
					out[xray.ProtocolVLESS] = map[string]any{
						"mtu":               icfg.MTU,
						"listen_port":       ib.Port,
						"server_names":      ib.ServerNames,
						"short_ids":         ib.ShortIDs,
						"flow":              ib.Flow,
						"server_public_key": pub,
					}
				case xray.ProtocolHysteria2:
					out[xray.ProtocolHysteria2] = map[string]any{
						"mtu":         icfg.MTU,
						"listen_port": ib.Port,
						"sni":         ib.SNI,
						"alpn":        []string{"h3"},
					}
				}
			}
		}
	}

	if len(out) == 0 {
		return nil
	}
	return out
}

// buildProtocols возвращает список протоколов, которые нода анонсирует API.
func buildProtocols(cfg *appconfig.AppConfig) []apiclient.Protocol {
	out := make([]apiclient.Protocol, 0, len(cfg.Router.Transports))
	seen := make(map[string]struct{})
	add := func(name string) {
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		out = append(out, apiclient.Protocol{Protocol: name, Capacity: 100})
	}
	for _, iconf := range cfg.Router.Transports {
		typ, _ := iconf["type"].(string)
		switch typ {
		case "awg":
			icfg, err := awg.ParseConfig(iconf)
			if err != nil {
				continue
			}
			add(icfg.Protocol)
		case "xray":
			icfg, err := xray.ParseConfig(iconf)
			if err != nil {
				continue
			}
			for _, p := range icfg.Protocols() {
				add(p)
			}
		}
	}
	return out
}
