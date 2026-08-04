package discovery

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/TexHik620953/liberator-node-go/pkg/mesh/session"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/topology"
	"github.com/TexHik620953/liberator-node-go/pkg/mesh/transport"
)

type nopPersister struct{}

func (nopPersister) Load() (map[string]*topology.PeerInfo, error) {
	return map[string]*topology.PeerInfo{}, nil
}
func (nopPersister) Save(map[string]*topology.PeerInfo) error { return nil }

// Регистр с фиксированным набором сессий — refreshPeers читает только Get/ListActive.
type fakeRegistry struct {
	sessions map[string]*session.Session
}

func (r *fakeRegistry) Get(peerID string) (*session.Session, bool) {
	s, ok := r.sessions[peerID]
	return s, ok
}

func (r *fakeRegistry) ListActive() []*session.Session {
	list := make([]*session.Session, 0, len(r.sessions))
	for _, s := range r.sessions {
		list = append(list, s)
	}
	return list
}

func (r *fakeRegistry) Add(*session.Session) error { return nil }
func (r *fakeRegistry) Remove(*session.Session)    {}
func (r *fakeRegistry) Close()                     {}
func (r *fakeRegistry) SubscribeNewSessions(context.Context) <-chan *session.Session {
	return nil
}

type stubConn struct{ addr string }

func (c *stubConn) ID() string                                     { return c.addr }
func (c *stubConn) RemoteAddr() net.Addr                           { return testAddress(c.addr) }
func (c *stubConn) OpenStream(context.Context) (net.Conn, error)   { return nil, nil }
func (c *stubConn) AcceptStream(context.Context) (net.Conn, error) { return nil, nil }
func (c *stubConn) SendDatagram([]byte) error                      { return nil }
func (c *stubConn) RecvDatagram(context.Context) ([]byte, error)   { return nil, nil }
func (c *stubConn) IsInitiator() bool                              { return true }
func (c *stubConn) Close() error                                   { return nil }
func (c *stubConn) Context() context.Context                       { return context.Background() }
func (c *stubConn) TotalSent() uint64                              { return 0 }
func (c *stubConn) TotalRecv() uint64                              { return 0 }

var _ transport.PeerConnection = (*stubConn)(nil)

func TestRefreshPeersKeepsLiveDropsStale(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const liveAddr = "1.1.1.1:9000"
	now := time.Now()
	old := now.Add(-2 * peerTTL)

	repo := topology.NewPeerRepository(ctx, nopPersister{})
	repo.InsertMerge(topology.PeerInfo{ID: "live", Address: liveAddr, LastSeen: old})
	repo.InsertMerge(topology.PeerInfo{ID: "gone", Address: "2.2.2.2:9000", LastSeen: old})

	tr := &blockingTransport{started: make(chan struct{})}
	ds := &DiscoverySyncer{
		repo: repo,
		registry: &fakeRegistry{sessions: map[string]*session.Session{
			"live": {PeerID: "live", Conn: &stubConn{addr: liveAddr}},
		}},
		transport: tr,
		localID:   "self",
		dialing:   make(map[string]struct{}),
	}

	ds.refreshPeers(ctx, now)

	p, ok := repo.Get("live")
	if !ok {
		t.Fatal("peer with a live session must survive the ttl sweep")
	}
	if p.LastSeen.Before(now) {
		t.Fatal("live peer must be refreshed, otherwise neighbours will expire it")
	}
	if p.Address != liveAddr {
		t.Fatalf("refresh must keep the known address, got %q", p.Address)
	}
	if _, ok := repo.Get("gone"); ok {
		t.Fatal("peer without a session and older than ttl must be dropped")
	}

	// Протухший ID той же ноды приезжает по gossip: живая запись с тем же адресом свежее,
	// поэтому мусор не должен осесть в сторе и породить дозвон на занятый адрес.
	repo.InsertMerge(topology.PeerInfo{ID: "stale-id", Address: liveAddr, LastSeen: old})
	if _, ok := repo.Get("stale-id"); ok {
		t.Fatal("stale id sharing the live address must be dropped")
	}

	time.Sleep(50 * time.Millisecond)
	if calls := tr.calls.Load(); calls != 0 {
		t.Fatalf("dial calls: got %d, want 0", calls)
	}
}
