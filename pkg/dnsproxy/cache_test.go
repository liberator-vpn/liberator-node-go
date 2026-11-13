package dnsproxy

import (
	"net"
	"testing"
	"time"
)

func TestCacheManyToMany(t *testing.T) {
	c := NewCache(CacheConfig{TTL: time.Minute, MaxEntries: 10})
	ip1 := net.ParseIP("1.2.3.4")
	ip2 := net.ParseIP("1.2.3.5")
	c.Put("example.com", []net.IP{ip1, ip2})
	c.Put("another.com", []net.IP{ip1})
	c.PutClient(100, "example.com", []net.IP{ip1, ip2})
	c.PutClient(100, "another.com", []net.IP{ip1})

	got, ok := c.Lookup("example.com.")
	if !ok || len(got) != 2 {
		t.Fatalf("example.com lookup = %v, %v", got, ok)
	}
	domains := c.GlobalDomains(ipToUint32(ip1))
	if len(domains) != 2 {
		t.Fatalf("global domains = %v", domains)
	}
	hits := c.DomainsForClient(100, ipToUint32(ip1))
	if len(hits) != 2 {
		t.Fatalf("client hits = %v", hits)
	}
}

func TestCacheTTLAndMaxEntries(t *testing.T) {
	c := NewCache(CacheConfig{TTL: 10 * time.Millisecond, MaxEntries: 2})
	c.Put("a.com", []net.IP{net.ParseIP("1.1.1.1")})
	c.Put("b.com", []net.IP{net.ParseIP("1.1.1.2")})
	if c.Len() != 2 {
		t.Fatalf("len = %d", c.Len())
	}
	c.Put("c.com", []net.IP{net.ParseIP("1.1.1.3")})
	if c.Len() > 2 {
		t.Fatalf("max_entries not enforced: %d", c.Len())
	}
	time.Sleep(20 * time.Millisecond)
	if _, ok := c.Lookup("c.com"); ok {
		t.Fatal("expired entry still present")
	}
	c.Cleanup()
	if c.Len() != 0 {
		t.Fatalf("cleanup left %d entries", c.Len())
	}
}

func ipToUint32(ip net.IP) uint32 {
	return uint32(ip[12])<<24 | uint32(ip[13])<<16 | uint32(ip[14])<<8 | uint32(ip[15])
}

func TestProtectedEntriesAreNotEvicted(t *testing.T) {
	c := NewCache(CacheConfig{TTL: time.Minute, MaxEntries: 1})
	c.Put("rule.com", []net.IP{net.ParseIP("1.1.1.1")})
	c.SetProtected([]string{"rule.com"})
	c.Put("flood.com", []net.IP{net.ParseIP("2.2.2.2")})
	if _, ok := c.Lookup("rule.com"); !ok {
		t.Fatal("protected domain was evicted")
	}
}
