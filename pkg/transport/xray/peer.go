package xray

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"
)

type XrayPeer struct {
	ctx        context.Context
	nodeID     string
	virtualIP  uint32
	localIP    net.IP
	name       string
	auth       string
	protocol   string
	transport  *XrayTransport
	expiration *time.Time

	lastSeenNanos atomic.Int64
	totalToPeer   atomic.Uint64
	totalFromPeer atomic.Uint64
}

func newXrayPeer(ctx context.Context, nodeID string, vip uint32, localIP net.IP, name, auth, protocol string, tr *XrayTransport, exp *time.Time) *XrayPeer {
	p := &XrayPeer{
		ctx:        ctx,
		nodeID:     nodeID,
		virtualIP:  vip,
		localIP:    localIP,
		name:       name,
		auth:       auth,
		protocol:   protocol,
		transport:  tr,
		expiration: exp,
	}
	p.lastSeenNanos.Store(time.Now().UnixNano())
	return p
}

func (p *XrayPeer) GetNodeID() string        { return p.nodeID }
func (p *XrayPeer) GetVirtualIP() uint32     { return p.virtualIP }
func (p *XrayPeer) Context() context.Context { return p.ctx }

func (p *XrayPeer) LastSeen() time.Time { return time.Unix(0, p.lastSeenNanos.Load()) }

func (p *XrayPeer) TouchLastSeen(now time.Time) {
	prev := p.lastSeenNanos.Load()
	if now.UnixNano()-prev < int64(time.Second) {
		return
	}
	p.lastSeenNanos.Store(now.UnixNano())
}

func (p *XrayPeer) SendDatagram(data []byte) error {
	if p.localIP == nil {
		return fmt.Errorf("xray: no local source for virtual_ip %s", uint32ToIP(p.virtualIP))
	}
	// Возвращаем пакет с virtual_ip обратно к локальному сокету Xray:
	// dst virtual_ip -> local_ip. Для входящего client→client трафика это
	// тоже безопасно: ядро либо доставит его существующему соединению, либо
	// отправит ICMP; произвольный inbound к proxy-клиенту невозможен.
	if !rewriteIPv4Destination(data, ipToUint32(p.localIP)) {
		return fmt.Errorf("xray: failed to rewrite destination to %s", p.localIP)
	}
	p.totalToPeer.Add(uint64(len(data)))
	return p.transport.writePacket(data, p.protocol)
}

func (p *XrayPeer) snapshotStats() (toPeer, fromPeer uint64, lastSeen time.Time) {
	toPeer = p.totalToPeer.Swap(0)
	fromPeer = p.totalFromPeer.Swap(0)
	lastSeen = p.LastSeen()
	return toPeer, fromPeer, lastSeen
}
