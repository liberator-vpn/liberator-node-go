package dnsproxy

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func startTestDNS(t *testing.T, ip string, delay time.Duration) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		if delay > 0 {
			time.Sleep(delay)
		}
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name: req.Question[0].Name, Rrtype: dns.TypeA,
				Class: dns.ClassINET, Ttl: 60,
			},
			A: net.ParseIP(ip).To4(),
		})
		_ = w.WriteMsg(resp)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func queryA(t *testing.T, name string) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestServerCachesFirstAndLaterAnswers(t *testing.T) {
	fast := startTestDNS(t, "1.2.3.4", 0)
	slow := startTestDNS(t, "1.2.3.5", 100*time.Millisecond)
	cache := NewCache(CacheConfig{TTL: time.Minute, MaxEntries: 10})
	srv, err := NewServer(t.Context(), ServerConfig{
		Upstreams: []string{fast, slow},
		Timeout:   500 * time.Millisecond,
	}, cache)
	if err != nil {
		t.Fatal(err)
	}

	client := uint32(0x64400005) // 100.64.0.5
	out := srv.HandleUDPQuery(client, queryA(t, "example.com"))
	if len(out) == 0 {
		t.Fatal("no DNS response")
	}
	var resp dns.Msg
	if err := resp.Unpack(out); err != nil {
		t.Fatal(err)
	}
	if len(resp.Answer) == 0 {
		t.Fatal("empty answer")
	}
	if _, ok := cache.Lookup("example.com"); !ok {
		t.Fatal("first answer not cached")
	}

	// Медленный upstream должен долиться в кэш.
	time.Sleep(250 * time.Millisecond)
	ips, ok := cache.Lookup("example.com")
	if !ok || len(ips) != 2 {
		t.Fatalf("cache after slow upstream = %v, %v", ips, ok)
	}
	hits := cache.DomainsForClient(client, ipToUint32(net.ParseIP("1.2.3.4")))
	if len(hits) != 1 || hits[0].Domain != "example.com" {
		t.Fatalf("client reverse = %v", hits)
	}
}
