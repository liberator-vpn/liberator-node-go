package xray

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/uuid"
	"github.com/liberator-vpn/liberator-node-go/internal/metrics"
	"github.com/liberator-vpn/liberator-node-go/internal/utils/netutils"
	"github.com/liberator-vpn/liberator-node-go/internal/utils/safemap"
	"github.com/liberator-vpn/liberator-node-go/pkg/model"
	"github.com/liberator-vpn/liberator-node-go/pkg/routingtable"
	"github.com/liberator-vpn/liberator-node-go/pkg/transport"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/tun"
)

var _ transport.Transport = (*XrayTransport)(nil)

type XrayTransport struct {
	ctx    context.Context
	cancel context.CancelFunc

	cfg    *TransportConfig
	router transport.Router
	nodeID string

	proxyTun tun.Device
	writeMu  sync.Mutex
	policy   *policyManager
	ipt      *iptables.IPTables

	peers safemap.Safemap[uint32, *XrayPeer]

	staticMu sync.Mutex
	static   map[uint32]UserConfig

	deltaChan chan transport.TransportPeerStats
	reloadCh  chan struct{}

	configPath string
	tempDir    string

	closed    atomic.Bool
	closeOnce sync.Once
}

func New(ctx context.Context, cfg *TransportConfig, router transport.Router, nodeID string) (*XrayTransport, error) {
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	if _, err := exec.LookPath(cfg.Binary); err != nil {
		return nil, fmt.Errorf("xray: binary %q not found: %w", cfg.Binary, err)
	}

	if err := deleteLinkAndWait(cfg.ProxyTUN); err != nil {
		return nil, fmt.Errorf("xray: remove stale proxy tun %s: %w", cfg.ProxyTUN, err)
	}
	dev, err := tun.CreateTUN(cfg.ProxyTUN, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("xray: create proxy tun %s: %w", cfg.ProxyTUN, err)
	}
	if link, err := netlink.LinkByName(cfg.ProxyTUN); err == nil {
		_ = netlink.LinkSetUp(link)
	}
	// Ответы из ноды приходят на proxy-TUN с dst=virtual_ip; reverse-path
	// filter не должен их отбрасывать.
	_ = os.WriteFile(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", cfg.ProxyTUN), []byte("0"), 0o644)

	policy, err := newPolicyManager(cfg.ProxyTUN, cfg.Dummy, cfg.LocalCIDR, cfg.RouteTableBase, cfg.RulePriorityBase)
	if err != nil {
		_ = dev.Close()
		_ = netlinkLinkDelByName(cfg.ProxyTUN)
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)
	t := &XrayTransport{
		ctx:       ctx,
		cancel:    cancel,
		cfg:       cfg,
		router:    router,
		nodeID:    nodeID,
		proxyTun:  dev,
		policy:    policy,
		peers:     safemap.New[uint32, *XrayPeer](),
		static:    make(map[uint32]UserConfig),
		deltaChan: make(chan transport.TransportPeerStats, 100),
		reloadCh:  make(chan struct{}, 1),
	}
	t.setupInputAccept()

	if err := t.initConfigPath(); err != nil {
		t.Close()
		return nil, err
	}

	for _, u := range cfg.Users {
		vip := netutils.IPStringToUint32(u.VirtualIP)
		if vip == 0 {
			t.Close()
			return nil, fmt.Errorf("xray: user %q has invalid virtual_ip %q", u.Name, u.VirtualIP)
		}
		if err := t.addPeer(&model.Peer{
			Protocol:  u.Protocol,
			Name:      u.Name,
			Auth:      u.Auth,
			VirtualIP: vip,
		}, u.Flow, true); err != nil {
			t.Close()
			return nil, fmt.Errorf("xray: static user %q: %w", u.Name, err)
		}
	}

	if err := t.writeConfig(); err != nil {
		t.Close()
		return nil, err
	}
	return t, nil
}

// setupInputAccept разрешает локальную доставку ответов, которые нода
// записывает в proxy-TUN (dst=local_ip). Без этого host INPUT policy DROP
// ломает TCP-соединения Xray. Ошибка не фатальна: в контейнере без iptables
// может использоваться nftables, но тогда это ответственность окружения.
func (t *XrayTransport) setupInputAccept() {
	ipt, err := iptables.New()
	if err != nil {
		log.Printf("xray: iptables unavailable, INPUT/OUTPUT accept for %s not installed: %v", t.cfg.ProxyTUN, err)
		return
	}
	t.ipt = ipt
	if err := ipt.AppendUnique("filter", "INPUT", "-i", t.cfg.ProxyTUN, "-j", "ACCEPT"); err != nil {
		log.Printf("xray: failed to add INPUT accept for %s: %v", t.cfg.ProxyTUN, err)
	}
	if err := ipt.AppendUnique("filter", "OUTPUT", "-o", t.cfg.ProxyTUN, "-j", "ACCEPT"); err != nil {
		log.Printf("xray: failed to add OUTPUT accept for %s: %v", t.cfg.ProxyTUN, err)
	}
}

func (t *XrayTransport) initConfigPath() error {
	if t.cfg.ConfigPath != "" {
		t.configPath = t.cfg.ConfigPath
		return os.MkdirAll(filepath.Dir(t.configPath), 0o700)
	}
	dir := t.cfg.StateDir
	if dir == "" {
		tmp, err := os.MkdirTemp("", "liberator-xray-")
		if err != nil {
			return fmt.Errorf("xray: create state dir: %w", err)
		}
		t.tempDir = tmp
		dir = tmp
	} else if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("xray: create state dir: %w", err)
	}
	t.configPath = filepath.Join(dir, "xray.json")
	return nil
}

func (t *XrayTransport) Type() string        { return "xray" }
func (t *XrayTransport) Protocols() []string { return t.cfg.Protocols() }

func (t *XrayTransport) DeltaChan() chan transport.TransportPeerStats { return t.deltaChan }

func (t *XrayTransport) Run() {
	go t.readLoop()
	go t.watchUsage()

	done := make(chan struct{})
	go func() {
		t.supervise()
		close(done)
	}()

	<-t.ctx.Done()
	t.Close()
	<-done
}

func (t *XrayTransport) Close() {
	t.closeOnce.Do(func() {
		t.closed.Store(true)
		t.cancel()
		if t.proxyTun != nil {
			_ = t.proxyTun.Close()
		}
		if t.policy != nil {
			t.policy.close()
		}
		if t.ipt != nil {
			_ = t.ipt.DeleteIfExists("filter", "INPUT", "-i", t.cfg.ProxyTUN, "-j", "ACCEPT")
			_ = t.ipt.DeleteIfExists("filter", "OUTPUT", "-o", t.cfg.ProxyTUN, "-j", "ACCEPT")
		}
		_ = netlinkLinkDelByName(t.cfg.ProxyTUN)
		if t.tempDir != "" {
			_ = os.RemoveAll(t.tempDir)
		}
	})
}

// CreatePeer идемпотентен: реконсилятор вызывает его каждые несколько секунд.
func (t *XrayTransport) CreatePeer(peerInfo *model.Peer) error {
	return t.addPeer(peerInfo, "", false)
}

func (t *XrayTransport) addPeer(peerInfo *model.Peer, flow string, static bool) error {
	if t.closed.Load() {
		return fmt.Errorf("xray transport is closed")
	}
	protocol := peerInfo.Protocol
	if protocol == "" {
		protocols := t.cfg.Protocols()
		if len(protocols) != 1 {
			return fmt.Errorf("protocol is required when multiple inbounds are configured")
		}
		protocol = protocols[0]
	}
	if _, ok := t.cfg.inbound(protocol); !ok {
		return fmt.Errorf("no inbound for protocol %q", protocol)
	}

	auth := peerInfo.Auth
	if auth == "" {
		if static {
			// Иначе сгенерированный UUID/пароль неоткуда взять оператору:
			// API пока не отдаёт proxy-конфиги.
			return fmt.Errorf("static user %q must set auth", peerInfo.Name)
		}
		var err error
		auth, err = generateAuth(protocol)
		if err != nil {
			return err
		}
	}
	name := peerInfo.Name
	if name == "" {
		name = fmt.Sprintf("%s-%s", protocol, netutils.Uint32ToIPString(peerInfo.VirtualIP))
	}
	vip := peerInfo.VirtualIP

	// Имя пользователя — ключ маршрутизации Xray (email/user). Дубликаты
	// с разными virtual_ip сделали бы маршрут неоднозначным.
	duplicate := false
	t.peers.ForeachCond(func(existingIP uint32, p *XrayPeer) bool {
		if existingIP != vip && p.name == name {
			duplicate = true
			return false
		}
		return true
	})
	if duplicate {
		return fmt.Errorf("user name %q is already used by another virtual_ip", name)
	}

	t.staticMu.Lock()
	oldStatic, isStatic := t.static[vip]
	t.staticMu.Unlock()
	if !static && isStatic {
		return fmt.Errorf("virtual_ip %s belongs to static user %q", netutils.Uint32ToIPString(vip), oldStatic.Name)
	}
	if static {
		t.staticMu.Lock()
		if old, ok := t.static[vip]; ok && old.Auth != auth {
			t.staticMu.Unlock()
			return fmt.Errorf("virtual_ip %s already belongs to user %q", netutils.Uint32ToIPString(vip), old.Name)
		}
		t.static[vip] = UserConfig{
			Name: name, Auth: auth, Protocol: protocol, Flow: flow,
			VirtualIP: netutils.Uint32ToIPString(vip),
		}
		t.staticMu.Unlock()
	}

	if existing, ok := t.peers.Get(vip); ok {
		if existing.auth == auth && existing.protocol == protocol {
			// Пир уже есть: обновляем только шейпер, без перезапуска Xray.
			if shaped, ok := t.router.GetRemoteRoutingObject(vip); ok {
				if sr, ok := shaped.(*routingtable.ShapedRoute); ok {
					speed, traffic := limitsOf(peerInfo)
					if sr.SetLimits(speed, traffic) {
						return nil
					}
				}
			}
			if peerInfo.SpeedLimitMbps == nil && peerInfo.TrafficLimitGb == nil {
				return nil
			}
		}
		t.removePeer(vip, true)
	}

	localIP, err := t.policy.addVIP(uint32ToIP(vip))
	if err != nil {
		return err
	}

	peer := newXrayPeer(t.ctx, t.nodeID, vip, localIP, name, auth, protocol, t, peerInfo.ExpirationDate)
	var route routingtable.RoutingObject = peer
	if peerInfo.SpeedLimitMbps != nil || peerInfo.TrafficLimitGb != nil {
		speed, traffic := limitsOf(peerInfo)
		route = routingtable.NewShapedRoute(peer, speed, traffic)
	}
	if err := t.router.AddRoutingObject(route); err != nil {
		t.policy.removeVIP(uint32ToIP(vip))
		return fmt.Errorf("add routing object: %w", err)
	}
	t.peers.Set(vip, peer)
	t.requestReload()
	return nil
}

func (t *XrayTransport) KickPeer(ip uint32) bool {
	return t.removePeer(ip, false)
}

// removePeer удаляет пира. allowStatic=true используется внутренне, когда
// надо пересоздать маршрут статического пользователя (например, сменился режим
// лимитирования), не удаляя саму запись пользователя из конфига.
func (t *XrayTransport) removePeer(ip uint32, allowStatic bool) bool {
	if t.closed.Load() {
		return false
	}
	_, ok := t.peers.Get(ip)
	if !ok {
		return false
	}
	t.staticMu.Lock()
	_, isStatic := t.static[ip]
	t.staticMu.Unlock()
	if isStatic && !allowStatic {
		return false
	}

	t.router.DeleteRoutingObject(ip)
	t.policy.removeVIP(uint32ToIP(ip))
	t.peers.Delete(ip)
	t.requestReload()
	return true
}

func (t *XrayTransport) ExistsPeer(ip uint32) bool {
	return t.peers.Exists(ip)
}

func (t *XrayTransport) GeneratePeerKeys(peer *model.Peer) error {
	auth, err := generateAuth(peer.Protocol)
	if err != nil {
		return err
	}
	peer.Auth = auth
	return nil
}

func (t *XrayTransport) GenerateClientConnectionString(peer *model.Peer, addr string, name string) (string, error) {
	u := UserConfig{
		Name: peer.Name, Auth: peer.Auth, Protocol: peer.Protocol,
		VirtualIP: netutils.Uint32ToIPString(peer.VirtualIP),
	}
	return t.cfg.ClientURI(u, addr, name)
}

func (t *XrayTransport) requestReload() {
	select {
	case t.reloadCh <- struct{}{}:
	default:
	}
}

func (t *XrayTransport) writeConfig() error {
	users, err := t.usersSnapshot()
	if err != nil {
		return err
	}
	data, err := t.cfg.BuildConfig(users)
	if err != nil {
		return err
	}
	tmp := t.configPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("xray: write config: %w", err)
	}
	if err := os.Rename(tmp, t.configPath); err != nil {
		return fmt.Errorf("xray: replace config: %w", err)
	}
	return nil
}

func (t *XrayTransport) usersSnapshot() ([]UserConfig, error) {
	t.staticMu.Lock()
	out := make([]UserConfig, 0, len(t.static))
	for vip, u := range t.static {
		if local, ok := t.policy.localForVIP(vip); ok {
			u.SendThrough = local.String()
		}
		out = append(out, u)
	}
	t.staticMu.Unlock()

	t.peers.Foreach(func(ip uint32, p *XrayPeer) {
		t.staticMu.Lock()
		_, isStatic := t.static[ip]
		t.staticMu.Unlock()
		if isStatic {
			return
		}
		u := UserConfig{
			Name: p.name, Auth: p.auth, Protocol: p.protocol,
			VirtualIP: netutils.Uint32ToIPString(ip),
		}
		if local, ok := t.policy.localForVIP(ip); ok {
			u.SendThrough = local.String()
		}
		out = append(out, u)
	})
	return out, nil
}

// wireguard tun на Linux работает с IFF_VNET_HDR: на каждый пакет нужен
// 10-байтный virtio-заголовок перед IP. offset=10 оставляет под него место.
const tunOffset = 10

func (t *XrayTransport) readLoop() {
	const batch = 64
	bufs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, tunOffset+65535)
	}
	sizes := make([]int, batch)

	for {
		n, err := t.proxyTun.Read(bufs, sizes, tunOffset)
		if err != nil {
			select {
			case <-t.ctx.Done():
				return
			default:
			}
			log.Printf("xray: proxy tun read failed: %v", err)
			time.Sleep(10 * time.Millisecond)
			continue
		}
		now := time.Now()
		for i := 0; i < n; i++ {
			if sizes[i] <= 0 || sizes[i] > len(bufs[i])-tunOffset {
				continue
			}
			data := bufs[i][tunOffset : tunOffset+sizes[i]]
			localSrc, ok := ipv4Source(data)
			if !ok {
				continue
			}
			vip, ok := t.policy.vipForLocal(localSrc)
			if !ok {
				// Пакет не от Xray-пользователя (например, случайный
				// локальный процесс) — не пускаем его в VPN-роутер.
				continue
			}
			if !rewriteIPv4Source(data, vip) {
				continue
			}
			msg, err := t.router.NewMessageCopyFrom(data)
			if err != nil {
				continue
			}
			protocol := "xray"
			if p, ok := t.peers.Get(msg.HoleInfo.SrcIP); ok {
				protocol = p.protocol
				p.TouchLastSeen(now)
				p.totalFromPeer.Add(uint64(sizes[i]))
			}
			metrics.ObserveTraffic(metrics.DirIn, metrics.PeerClient, protocol, sizes[i])
			t.router.HandleTransportPacket(msg)
		}
	}
}

func (t *XrayTransport) writePacket(data []byte, protocol string) error {
	metrics.ObserveTraffic(metrics.DirOut, metrics.PeerClient, protocol, len(data))
	buf := make([]byte, tunOffset+len(data))
	copy(buf[tunOffset:], data)
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	_, err := t.proxyTun.Write([][]byte{buf}, tunOffset)
	return err
}

func (t *XrayTransport) watchUsage() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-ticker.C:
			t.peers.Foreach(func(_ uint32, p *XrayPeer) {
				toPeer, fromPeer, lastSeen := p.snapshotStats()
				select {
				case t.deltaChan <- transport.TransportPeerStats{
					VirtualIP: p.virtualIP, LastSeen: lastSeen,
					DeltaToPeer: toPeer, DeltaFromPeer: fromPeer,
				}:
				default:
					p.totalToPeer.Add(toPeer)
					p.totalFromPeer.Add(fromPeer)
				}
			})
		}
	}
}

func (t *XrayTransport) supervise() {
	backoff := time.Second
	for {
		if t.ctx.Err() != nil {
			return
		}
		if err := t.writeConfig(); err != nil {
			log.Printf("xray: config write failed: %v", err)
			if !sleepCtx(t.ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}

		cmd := exec.Command(t.cfg.Binary, "run", "-c", t.configPath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			log.Printf("xray: start failed: %v", err)
			if !sleepCtx(t.ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}

		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()

		select {
		case <-t.ctx.Done():
			stopProcess(cmd, done)
			return
		case <-t.reloadCh:
			stopProcess(cmd, done)
			backoff = time.Second
			continue
		case err := <-done:
			if t.ctx.Err() != nil {
				return
			}
			log.Printf("xray: process exited: %v (restart in %s)", err, backoff)
			if !sleepCtx(t.ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff)
		}
	}
}

func stopProcess(cmd *exec.Cmd, done <-chan error) {
	if cmd.Process != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-done
	}
}

func nextBackoff(d time.Duration) time.Duration {
	d *= 2
	if d > 60*time.Second {
		return 60 * time.Second
	}
	return d
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func generateAuth(protocol string) (string, error) {
	switch protocol {
	case ProtocolVLESS:
		return uuid.NewString(), nil
	case ProtocolHysteria2:
		buf := make([]byte, 24)
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		return hex.EncodeToString(buf), nil
	default:
		return "", fmt.Errorf("xray: unsupported protocol %q", protocol)
	}
}

func limitsOf(peerInfo *model.Peer) (speed *uint64, traffic *uint64) {
	if peerInfo.SpeedLimitMbps != nil {
		v := uint64((*peerInfo.SpeedLimitMbps) * 1024 * 1024)
		speed = &v
	}
	if peerInfo.TrafficLimitGb != nil {
		total := *peerInfo.TrafficLimitGb * 1024 * 1024 * 1024
		used := float64(peerInfo.FromPeerTotal + peerInfo.ToPeerTotal)
		if remaining := total - used; remaining > 0 {
			v := uint64(remaining)
			traffic = &v
		} else {
			v := uint64(0)
			traffic = &v
		}
	}
	return speed, traffic
}

func netlinkLinkDelByName(name string) error {
	return deleteLinkAndWait(name)
}

// deleteLinkAndWait удаляет линк и ждёт, пока ядро уберёт его из списка.
// Без ожидания CreateTUN с тем же именем может получить EINVAL: netlink
// обрабатывает удаление асинхронно.
func deleteLinkAndWait(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil
	}
	if err := netlink.LinkDel(link); err != nil {
		return err
	}
	for i := 0; i < 100; i++ {
		if _, err := netlink.LinkByName(name); err != nil {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("link %s did not disappear", name)
}
