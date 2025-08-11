package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type NoEDNSResolver struct {
	servers []string
	timeout time.Duration
	network string
}

func NewNoEDNSResolver() *NoEDNSResolver {
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	servers := []string{"127.0.0.1:53"}
	if err == nil && len(cfg.Servers) > 0 {
		servers = servers[:0]
		for _, s := range cfg.Servers {
			host := s
			if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
				host = "[" + host + "]"
			}
			port := cfg.Port
			if port == "" {
				port = "53"
			}
			servers = append(servers, net.JoinHostPort(host, port))
		}
	}
	return &NoEDNSResolver{servers: servers, timeout: 2 * time.Second, network: "udp"}
}

func (r *NoEDNSResolver) lookupQtype(ctx context.Context, name string, qtype uint16) (net.IP, error) {
	q := new(dns.Msg)
	q.Id = dns.Id()
	q.RecursionDesired = true
	q.Question = []dns.Question{{
		Name:   dns.Fqdn(name),
		Qtype:  qtype,
		Qclass: dns.ClassINET,
	}}
	c := &dns.Client{Net: r.network, Timeout: r.timeout, SingleInflight: true}
	for _, srv := range r.servers {
		in, _, err := c.ExchangeContext(ctx, q, srv)
		if err != nil {
			continue
		}
		if in == nil || in.Rcode != dns.RcodeSuccess {
			continue
		}
		for _, ans := range in.Answer {
			switch rr := ans.(type) {
			case *dns.A:
				if qtype == dns.TypeA && rr.A != nil {
					return rr.A, nil
				}
			case *dns.AAAA:
				if qtype == dns.TypeAAAA && rr.AAAA != nil {
					return rr.AAAA, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("no %s record for %s", dns.TypeToString[qtype], name)
}

func (r *NoEDNSResolver) LookupAnyOnce(ctx context.Context, name string) (net.IP, error) {
	if ip, err := r.lookupQtype(ctx, name, dns.TypeA); err == nil {
		return ip, nil
	}
	if ip6, err := r.lookupQtype(ctx, name, dns.TypeAAAA); err == nil {
		return ip6, nil
	}
	return nil, fmt.Errorf("no A/AAAA records for %s", name)
}
