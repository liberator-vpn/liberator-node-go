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

	ifaceDropped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "node",
		Name:      "iface_dropped_packets_total",
		Help:      "Packets dropped because the TUN writer queue is full.",
	}, []string{"dir"})

	policyDroppedRules = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "node",
		Name:      "policy_dropped_rules_total",
		Help:      "Rules dropped while applying the desired policy (invalid format).",
	})

	tunWriteBytes = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "node",
		Name:      "tun_write_bytes_total",
		Help:      "Bytes written to the kernel TUN device.",
	})
	tunWritePackets = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "node",
		Name:      "tun_write_packets_total",
		Help:      "Packets submitted to the kernel TUN device.",
	})
	tunWriteErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "node",
		Name:      "tun_write_errors_total",
		Help:      "TUN write calls that returned an error.",
	})
	tunWriteZero = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "node",
		Name:      "tun_write_zero_total",
		Help:      "TUN write calls that wrote zero bytes for a non-empty batch.",
	})
	tunOversizeDrops = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "node",
		Name:      "tun_oversize_drops_total",
		Help:      "Packets dropped before TUN because they exceeded the TUN MTU.",
	})
	awgParseErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "node",
		Name:      "awg_parse_errors_total",
		Help:      "Decrypted AWG packets that could not be parsed into a datagram message.",
	})
	ifaceReadBatches = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "node",
		Name:      "iface_read_batches_total",
		Help:      "Batches read from the kernel TUN device.",
	})
	ifaceReadPackets = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "node",
		Name:      "iface_read_packets_total",
		Help:      "Packets read from the kernel TUN device.",
	})
)

func init() {
	prometheus.MustRegister(
		trafficBytes, packetLifetime, connectedPeers, activeClients, ifaceDropped, policyDroppedRules,
		tunWriteBytes, tunWritePackets, tunWriteErrors, tunWriteZero, tunOversizeDrops,
		awgParseErrors, ifaceReadBatches, ifaceReadPackets,
	)
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

// ObserveIfaceDrop учитывает пакет, отброшенный при переполнении очереди TUN.
func ObserveIfaceDrop(dir string) { ifaceDropped.WithLabelValues(dir).Inc() }

// ObservePolicyDrop учитывает правила, отброшенные при применении политики.
func ObservePolicyDrop(n int) { policyDroppedRules.Add(float64(n)) }

// ObserveTUNWrite учитывает байты и пакеты, отправленные в kernel TUN.
func ObserveTUNWrite(bytes, packets int) {
	tunWriteBytes.Add(float64(bytes))
	tunWritePackets.Add(float64(packets))
}

// ObserveTUNWriteError учитывает ошибку Write в TUN.
func ObserveTUNWriteError() { tunWriteErrors.Inc() }

// ObserveTUNWriteZero учитывает Write, который не записал ни одного байта.
func ObserveTUNWriteZero() { tunWriteZero.Inc() }

// ObserveTUNOversizeDrop учитывает пакет, не влезший в MTU TUN.
func ObserveTUNOversizeDrop() { tunOversizeDrops.Inc() }

// ObserveAWGParseError учитывает пакет, который не удалось разобрать после AWG.
func ObserveAWGParseError() { awgParseErrors.Inc() }

// ObserveIfaceReadBatch учитывает батч и число пакетов, прочитанных из TUN.
func ObserveIfaceReadBatch(packets int) {
	ifaceReadBatches.Inc()
	ifaceReadPackets.Add(float64(packets))
}

// Handler возвращает HTTP-хендлер /metrics поверх default-регистра (включая
// Go/process-коллекторы).
func Handler() http.Handler {
	return promhttp.Handler()
}
