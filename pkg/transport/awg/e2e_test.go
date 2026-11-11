package awg

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	amneziawgdevice "github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun"
	"github.com/liberator-vpn/liberator-node-go/internal/utils/dgmessage"
	"github.com/liberator-vpn/liberator-node-go/pkg/model"
	"github.com/liberator-vpn/liberator-node-go/pkg/routingtable"
)

type testRouter struct {
	pool   dgmessage.DGMessagePool
	mu     sync.Mutex
	routes map[uint32]routingtable.RoutingObject
	in     chan *dgmessage.DatagramMessage
}

func newTestRouter() *testRouter {
	return &testRouter{
		pool:   dgmessage.NewDGMessagePool(65535),
		routes: make(map[uint32]routingtable.RoutingObject),
		in:     make(chan *dgmessage.DatagramMessage, 16),
	}
}

func (r *testRouter) AddRoutingObject(obj routingtable.RoutingObject) error {
	r.mu.Lock()
	r.routes[obj.GetVirtualIP()] = obj
	r.mu.Unlock()
	return nil
}
func (r *testRouter) DeleteRoutingObject(ip uint32) error {
	r.mu.Lock()
	delete(r.routes, ip)
	r.mu.Unlock()
	return nil
}
func (r *testRouter) GetRemoteRoutingObject(ip uint32) (routingtable.RoutingObject, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	obj, ok := r.routes[ip]
	return obj, ok
}
func (r *testRouter) NewMessageCopyFrom(data []byte) (*dgmessage.DatagramMessage, error) {
	return r.pool.NewMessageCopyFrom(data)
}
func (r *testRouter) HandleTransportPacket(p *dgmessage.DatagramMessage) {
	r.in <- p
}

type memTun struct {
	toDevice chan []byte
	fromDev  chan []byte
	events   chan tun.Event
	closed   chan struct{}
	once     sync.Once
	mtu      int
}

func newMemTun(mtu int) *memTun {
	return &memTun{
		toDevice: make(chan []byte, 16),
		fromDev:  make(chan []byte, 16),
		events:   make(chan tun.Event, 1),
		closed:   make(chan struct{}),
		mtu:      mtu,
	}
}
func (t *memTun) File() *os.File        { return nil }
func (t *memTun) Name() (string, error) { return "memtun", nil }
func (t *memTun) BatchSize() int        { return 1 }
func (t *memTun) Close() error {
	t.once.Do(func() {
		close(t.events)
		close(t.closed)
	})
	return nil
}
func (t *memTun) Events() <-chan tun.Event { return t.events }
func (t *memTun) MTU() (int, error)        { return t.mtu, nil }
func (t *memTun) Write(bufs [][]byte, offset int) (int, error) {
	n := 0
	for _, b := range bufs {
		pkt := append([]byte(nil), b[offset:]...)
		select {
		case t.fromDev <- pkt:
			n++
		case <-t.closed:
			return n, nil
		}
	}
	return n, nil
}
func (t *memTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case pkt := <-t.toDevice:
		copy(bufs[0][offset:], pkt)
		sizes[0] = len(pkt)
		return 1, nil
	case <-t.closed:
		return 0, os.ErrClosed
	}
}

func TestAWGEndToEnd(t *testing.T) {
	port := freeUDPPort(t)

	serverPriv := randHex(t)
	serverCfg := &TransportConfig{
		MTU: 1376, ListenPort: port, PrivateKey: serverPriv,
		H1: "1245955480-1579617642", H2: "1827874969-1854585193",
		H3: "2137919667-2143439009", H4: "2147159423-2147402519",
		Jc: 5, JMin: 70, JMax: 120, S1: 48, S2: 27, S3: 30, S4: 7,
	}
	router := newTestRouter()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := New(ctx, serverCfg, router, "server")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); srv.Close() }()

	clientPriv := randHex(t)
	clientPub, err := ServerPublicKey(clientPriv)
	if err != nil {
		t.Fatal(err)
	}
	serverPub, err := ServerPublicKey(serverPriv)
	if err != nil {
		t.Fatal(err)
	}
	clientVIP := ipToUint32(net.ParseIP("100.64.0.2"))
	if err := srv.CreatePeer(&model.Peer{VirtualIP: clientVIP, AwgPublicKey: clientPub}); err != nil {
		t.Fatal(err)
	}

	ct := newMemTun(1376)
	clientDev := amneziawgdevice.NewDevice(ct, conn.NewDefaultBind(), amneziawgdevice.NewLogger(amneziawgdevice.LogLevelError, "(client) "))
	defer clientDev.Close()
	deviceIPC := "private_key=" + clientPriv + "\nlisten_port=0\n" +
		"h1=" + serverCfg.H1 + "\nh2=" + serverCfg.H2 + "\nh3=" + serverCfg.H3 + "\nh4=" + serverCfg.H4 + "\n" +
		"s1=" + itoa(serverCfg.S1) + "\ns2=" + itoa(serverCfg.S2) + "\ns3=" + itoa(serverCfg.S3) + "\ns4=" + itoa(serverCfg.S4) + "\n" +
		"jc=" + itoa(serverCfg.Jc) + "\njmin=" + itoa(serverCfg.JMin) + "\njmax=" + itoa(serverCfg.JMax) + "\n"
	if err := clientDev.IpcSet(deviceIPC); err != nil {
		t.Fatal(err)
	}
	peerIPC := "public_key=" + serverPub + "\nendpoint=127.0.0.1:" + itoa(port) + "\nallowed_ip=0.0.0.0/0\n" +
		"persistent_keepalive_interval=1\n"
	if err := clientDev.IpcSet(peerIPC); err != nil {
		t.Fatal(err)
	}
	if err := clientDev.Up(); err != nil {
		t.Fatal(err)
	}

	// client -> server
	pkt := udpPacket(clientVIP, 0x08080808, 12345, 53, []byte("ping"))
	ct.toDevice <- pkt
	select {
	case got := <-router.in:
		defer got.Free()
		if got.HoleInfo.SrcIP != clientVIP {
			t.Fatalf("server got src %s", ipString(got.HoleInfo.SrcIP))
		}
		if got.HoleInfo.Protocol != "udp" {
			t.Fatalf("protocol = %s", got.HoleInfo.Protocol)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client packet did not reach server")
	}

	// server -> client
	route, ok := router.GetRemoteRoutingObject(clientVIP)
	if !ok {
		t.Fatal("route object missing")
	}
	reply := udpPacket(0x08080808, clientVIP, 53, 12345, []byte("pong"))
	if err := route.SendDatagram(reply); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-ct.fromDev:
		if string(got[28:]) != "pong" {
			t.Fatalf("client got payload %q", got[28:])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server packet did not reach client")
	}
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func randHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	b[0] &= 248
	b[31] &= 127
	b[31] |= 64
	return hex.EncodeToString(b)
}

func udpPacket(src, dst uint32, sport, dport uint16, payload []byte) []byte {
	pkt := make([]byte, 20+8+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 17
	binary.BigEndian.PutUint32(pkt[12:16], src)
	binary.BigEndian.PutUint32(pkt[16:20], dst)
	binary.BigEndian.PutUint16(pkt[20:22], sport)
	binary.BigEndian.PutUint16(pkt[22:24], dport)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(8+len(payload)))
	copy(pkt[28:], payload)
	return pkt
}

func itoa(n int) string {
	return strconv.Itoa(n)
}

func ipToUint32(ip net.IP) uint32 {
	v4 := ip.To4()
	return binary.BigEndian.Uint32(v4)
}

func ipString(v uint32) string {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).String()
}
