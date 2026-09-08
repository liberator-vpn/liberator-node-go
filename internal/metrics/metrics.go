// Package metrics собирает наблюдаемость ноды и отдаёт /metrics в формате
// Prometheus. Нода пассивна и не имеет авторизации; метрики в открытом виде.
package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Направление и источник/приёмник трафика.
const (
	DirIn  = "in"
	DirOut = "out"

	PeerClient   = "client"   // клиент VPN
	PeerInternet = "internet" // выход/вход через TUN (NAT)
	PeerNode     = "node"     // другая нода (QUIC-пул)

	// NoProtocol — значения label protocol, когда туннельного протокола нет
	// (например, leg интернета через TUN).
	NoProtocol = ""
)

var (
	trafficBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "node",
		Name:      "traffic_bytes_total",
		Help:      "Bytes forwarded, by direction, peer and tunnel protocol.",
	}, []string{"dir", "peer", "protocol"})

	packetLifetime = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "node",
		Name:      "packet_lifetime_seconds",
		Help:      "Time a packet spends in the node: NewMessageCopyFrom -> Free.",
		Buckets:   prometheus.ExponentialBuckets(1e-6, 2, 22), // ~1µs .. ~4s
	})

	connectedPeers = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "node",
		Name:      "connected_peers",
		Help:      "Number of live QUIC connections to other nodes.",
	})

	activeClients = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "node",
		Name:      "active_clients",
		Help:      "Number of provisioned/active VPN clients.",
	})
)

func init() {
	prometheus.MustRegister(trafficBytes, packetLifetime, connectedPeers, activeClients)
}

// ObserveTraffic учитывает прошедшие байты по направлению, peer'у и протоколу.
func ObserveTraffic(dir, peer, protocol string, n int) {
	trafficBytes.WithLabelValues(dir, peer, protocol).Add(float64(n))
}

// ObservePacketLifetime учитывает время жизни пакета.
func ObservePacketLifetime(d time.Duration) {
	packetLifetime.Observe(d.Seconds())
}

func SetActiveClients(n int) { activeClients.Set(float64(n)) }
func SetConnectedPeers(n int) {
	connectedPeers.Set(float64(n))
}

// Handler возвращает HTTP-хендлер /metrics поверх default-регистра (включая
// Go/process-коллекторы).
func Handler() http.Handler {
	return promhttp.Handler()
}
