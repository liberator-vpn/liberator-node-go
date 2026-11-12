package dnsproxy

import (
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/liberator-vpn/liberator-node-go/internal/utils/netutils"
)

type CacheConfig struct {
	TTL        time.Duration
	MaxEntries int
}

type entry struct {
	ips       map[uint32]struct{}
	expiresAt time.Time
	lastUsed  time.Time
}

// Hit — домен, который клиент запрашивал для данного IP.
type Hit struct {
	Domain   string
	LastSeen time.Time
}

// Cache хранит many-to-many:
//
//	domain -> set(IP)
//	IP     -> set(domain)
//	client -> IP -> set(domain)
type Cache struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxEntries int
	forward    map[string]*entry
	reverse    map[uint32]map[string]struct{}
	clients    map[uint32]map[uint32]map[string]time.Time
}

func NewCache(cfg CacheConfig) *Cache {
	if cfg.TTL <= 0 {
		cfg.TTL = 5 * time.Minute
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 10000
	}
	return &Cache{
		ttl:        cfg.TTL,
		maxEntries: cfg.MaxEntries,
		forward:    make(map[string]*entry),
		reverse:    make(map[uint32]map[string]struct{}),
		clients:    make(map[uint32]map[uint32]map[string]time.Time),
	}
}

func normalizeDomain(d string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
}

// Put добавляет/обновляет IP домена. IP объединяются: разные upstream'ы
// могут вернуть разные GeoDNS-наборы, и все они должны быть известны правилам.
func (c *Cache) Put(domain string, ips []net.IP) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.forward[domain]
	if !ok {
		e = &entry{ips: make(map[uint32]struct{})}
		c.forward[domain] = e
	}
	e.expiresAt = now.Add(c.ttl)
	e.lastUsed = now
	for _, ip := range ips {
		n := netutils.IPToUint32(ip)
		if n == 0 {
			continue
		}
		e.ips[n] = struct{}{}
		set := c.reverse[n]
		if set == nil {
			set = make(map[string]struct{})
			c.reverse[n] = set
		}
		set[domain] = struct{}{}
	}
	c.evictLocked(now)
}

// PutClient связывает клиента с IP и доменом, который он запрашивал.
func (c *Cache) PutClient(clientIP uint32, domain string, ips []net.IP) {
	domain = normalizeDomain(domain)
	if clientIP == 0 || domain == "" {
		return
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	byIP := c.clients[clientIP]
	if byIP == nil {
		byIP = make(map[uint32]map[string]time.Time)
		c.clients[clientIP] = byIP
	}
	for _, ip := range ips {
		n := netutils.IPToUint32(ip)
		if n == 0 {
			continue
		}
		set := byIP[n]
		if set == nil {
			set = make(map[string]time.Time)
			byIP[n] = set
		}
		set[domain] = now
	}
}

// Lookup возвращает IP домена из кэша.
func (c *Cache) Lookup(domain string) ([]net.IP, bool) {
	domain = normalizeDomain(domain)
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.forward[domain]
	if !ok {
		return nil, false
	}
	if now.After(e.expiresAt) {
		c.removeDomainLocked(domain, e)
		return nil, false
	}
	e.lastUsed = now
	out := make([]net.IP, 0, len(e.ips))
	for n := range e.ips {
		out = append(out, net.ParseIP(netutils.Uint32ToIPString(n)))
	}
	return out, true
}

// GlobalDomains возвращает все домены, которые указывали на IP.
func (c *Cache) GlobalDomains(ip uint32) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	set := c.reverse[ip]
	if len(set) == 0 {
		return nil
	}
	now := time.Now()
	out := make([]string, 0, len(set))
	for d := range set {
		if e, ok := c.forward[d]; ok && !now.After(e.expiresAt) {
			out = append(out, d)
		}
	}
	return out
}

// DomainsForClient возвращает домены клиента для IP, отсортированные по
// последнему запросу (свежие первыми).
func (c *Cache) DomainsForClient(clientIP, ip uint32) []Hit {
	c.mu.Lock()
	defer c.mu.Unlock()
	byIP := c.clients[clientIP]
	if byIP == nil {
		return nil
	}
	set := byIP[ip]
	if len(set) == 0 {
		return nil
	}
	now := time.Now()
	out := make([]Hit, 0, len(set))
	for d, seen := range set {
		if now.Sub(seen) > c.ttl*2 {
			delete(set, d)
			continue
		}
		// Домен мог быть вытеснен из forward cache — тогда правило не применяем.
		if e, ok := c.forward[d]; !ok || now.After(e.expiresAt) {
			delete(set, d)
			continue
		}
		out = append(out, Hit{Domain: d, LastSeen: seen})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

// Cleanup удаляет просроченные записи и чистит reverse index.
func (c *Cache) Cleanup() {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for d, e := range c.forward {
		if now.After(e.expiresAt) {
			c.removeDomainLocked(d, e)
		}
	}
	for client, byIP := range c.clients {
		for ip, set := range byIP {
			for d, seen := range set {
				if now.Sub(seen) > c.ttl*2 {
					delete(set, d)
				}
			}
			if len(set) == 0 {
				delete(byIP, ip)
			}
		}
		if len(byIP) == 0 {
			delete(c.clients, client)
		}
	}
}

func (c *Cache) evictLocked(now time.Time) {
	for len(c.forward) > c.maxEntries {
		var oldestDomain string
		var oldest *entry
		for d, e := range c.forward {
			if oldest == nil || e.lastUsed.Before(oldest.lastUsed) {
				oldestDomain, oldest = d, e
			}
		}
		if oldest == nil {
			return
		}
		c.removeDomainLocked(oldestDomain, oldest)
	}
}

func (c *Cache) removeDomainLocked(domain string, e *entry) {
	delete(c.forward, domain)
	for ip := range e.ips {
		set := c.reverse[ip]
		if set == nil {
			continue
		}
		delete(set, domain)
		if len(set) == 0 {
			delete(c.reverse, ip)
		}
	}
}

func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.forward)
}
