package dnsproxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/liberator-vpn/liberator-node-go/internal/utils/netutils"
	"github.com/miekg/dns"
)

type ServerConfig struct {
	ListenAddr string
	ListenPort int
	Upstreams  []string
	Timeout    time.Duration
}

type Server struct {
	cfg   ServerConfig
	cache *Cache
	udp   *dns.Server
	tcp   *dns.Server
	ctx   context.Context
}

func NewServer(ctx context.Context, cfg ServerConfig, cache *Cache) (*Server, error) {
	if cache == nil {
		return nil, fmt.Errorf("dnsproxy: cache is required")
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "0.0.0.0"
	}
	if cfg.ListenPort <= 0 {
		cfg.ListenPort = 53
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	if len(cfg.Upstreams) == 0 {
		cfg.Upstreams = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	addr := net.JoinHostPort(cfg.ListenAddr, strconv.Itoa(cfg.ListenPort))
	s := &Server{cfg: cfg, cache: cache, ctx: ctx}
	s.udp = &dns.Server{Addr: addr, Net: "udp", Handler: s}
	s.tcp = &dns.Server{Addr: addr, Net: "tcp", Handler: s}
	return s, nil
}

func (s *Server) Run() {
	go func() {
		if err := s.udp.ListenAndServe(); err != nil && s.ctx.Err() == nil {
			log.Printf("dnsproxy: udp server failed: %v", err)
		}
	}()
	go func() {
		if err := s.tcp.ListenAndServe(); err != nil && s.ctx.Err() == nil {
			log.Printf("dnsproxy: tcp server failed: %v", err)
		}
	}()
	log.Printf("dnsproxy: listening on %s", s.udp.Addr)

	janitor := time.NewTicker(time.Minute)
	defer janitor.Stop()
	for {
		select {
		case <-s.ctx.Done():
			s.Close()
			return
		case <-janitor.C:
			s.cache.Cleanup()
		}
	}
}

func (s *Server) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.udp.ShutdownContext(ctx)
	_ = s.tcp.ShutdownContext(ctx)
}

func (s *Server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	clientIP := remoteIP(w.RemoteAddr())
	resp, err := s.resolve(context.Background(), req, clientIP)
	if err != nil {
		resp = new(dns.Msg)
		resp.SetRcode(req, dns.RcodeServerFailure)
	}
	_ = w.WriteMsg(resp)
}

// HandleUDPQuery используется роутером для перехвата DNS-запросов,
// отправленных не на gateway (например, на 8.8.8.8).
func (s *Server) HandleUDPQuery(clientIP uint32, query []byte) []byte {
	var req dns.Msg
	if err := req.Unpack(query); err != nil {
		return nil
	}
	resp, err := s.resolve(context.Background(), &req, clientIP)
	if err != nil {
		return nil
	}
	out, err := resp.Pack()
	if err != nil {
		return nil
	}
	return out
}

func (s *Server) resolve(ctx context.Context, req *dns.Msg, clientIP uint32) (*dns.Msg, error) {
	if len(req.Question) == 0 {
		return nil, fmt.Errorf("dnsproxy: empty question")
	}
	q := req.Question[0]
	if q.Qtype != dns.TypeA {
		// IPv6 и прочие типы пока не кэшируем и не используем для правил.
		return s.queryAll(ctx, req, nil)
	}

	if ips, ok := s.cache.Lookup(q.Name); ok {
		if clientIP != 0 {
			s.cache.PutClient(clientIP, q.Name, ips)
		}
		return buildAResponse(req, ips, s.cache.ttl), nil
	}
	return s.queryAll(ctx, req, func(resp *dns.Msg) {
		ips := aRecords(resp)
		if len(ips) == 0 {
			return
		}
		s.cache.Put(q.Name, ips)
		if clientIP != 0 {
			s.cache.PutClient(clientIP, q.Name, ips)
		}
	})
}

// queryAll отправляет запрос во все upstream'ы параллельно. Первый ответ
// возвращается клиенту, остальные продолжают выполняться и доливаются в кэш.
func (s *Server) queryAll(ctx context.Context, req *dns.Msg, onAnswer func(*dns.Msg)) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	ch := make(chan *dns.Msg, len(s.cfg.Upstreams))
	var wg sync.WaitGroup
	for _, upstream := range s.cfg.Upstreams {
		wg.Add(1)
		go func(upstream string) {
			defer wg.Done()
			c := &dns.Client{Net: "udp", Timeout: s.cfg.Timeout}
			resp, _, err := c.ExchangeContext(ctx, req.Copy(), upstream)
			if err != nil || resp == nil {
				return
			}
			select {
			case ch <- resp:
			case <-ctx.Done():
			}
		}(upstream)
	}
	go func() {
		wg.Wait()
		close(ch)
	}()

	var first *dns.Msg
	select {
	case resp, ok := <-ch:
		if ok {
			first = resp
		}
	case <-ctx.Done():
		cancel()
		return nil, ctx.Err()
	}
	if first == nil {
		cancel()
		return nil, fmt.Errorf("dnsproxy: all upstreams failed")
	}
	first.Id = req.Id
	if onAnswer != nil {
		onAnswer(first)
	}
	go func() {
		defer cancel()
		for resp := range ch {
			if resp != nil && onAnswer != nil {
				onAnswer(resp)
			}
		}
	}()
	return first, nil
}

func aRecords(resp *dns.Msg) []net.IP {
	out := make([]net.IP, 0, len(resp.Answer))
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			out = append(out, a.A)
		}
	}
	return out
}

func buildAResponse(req *dns.Msg, ips []net.IP, ttl time.Duration) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	ttlSec := uint32(ttl.Seconds())
	if ttlSec == 0 {
		ttlSec = 1
	}
	for _, ip := range ips {
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name: req.Question[0].Name, Rrtype: dns.TypeA,
				Class: dns.ClassINET, Ttl: ttlSec,
			},
			A: ip,
		})
	}
	return resp
}

func remoteIP(addr net.Addr) uint32 {
	if addr == nil {
		return 0
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	host = strings.Trim(host, "[]")
	return netutils.IPStringToUint32(host)
}
