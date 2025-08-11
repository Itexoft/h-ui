package dnsresolver

import (
	"context"
	"errors"
	"net"
	"runtime"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type Resolver struct {
	servers []string
	timeout time.Duration
}

func New() *Resolver {
	s := []string{"127.0.0.1:53", "[::1]:53"}
	if runtime.GOOS != "windows" {
		if cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil && len(cfg.Servers) > 0 {
			for _, h := range cfg.Servers {
				host := h
				if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
					host = "[" + host + "]"
				}
				port := cfg.Port
				if port == "" {
					port = "53"
				}
				s = append(s, net.JoinHostPort(host, port))
			}
		}
	}
	return &Resolver{servers: s, timeout: 2 * time.Second}
}

func (r *Resolver) lookupOne(ctx context.Context, name string, qtype uint16, depth int) ([]net.IP, error) {
	if depth >= 10 {
		return nil, errors.New("cname loop")
	}
	q := new(dns.Msg)
	q.Id = dns.Id()
	q.RecursionDesired = true
	q.Question = []dns.Question{{Name: dns.Fqdn(name), Qtype: qtype, Qclass: dns.ClassINET}}
	try := func(netw, srv string) (*dns.Msg, error) {
		c := &dns.Client{Net: netw, Timeout: r.timeout, SingleInflight: true}
		m, _, err := c.ExchangeContext(ctx, q, srv)
		return m, err
	}
	var last error
	for _, srv := range r.servers {
		in, err := try("udp", srv)
		if err != nil || in == nil {
			if in == nil {
				if in2, err2 := try("tcp", srv); err2 == nil && in2 != nil {
					in = in2
					err = nil
				} else {
					if err2 != nil {
						last = err2
					} else {
						last = err
					}
					continue
				}
			} else {
				last = err
			}
		}
		if in.Truncated {
			if in2, err2 := try("tcp", srv); err2 == nil && in2 != nil {
				in = in2
			} else {
				if err2 != nil {
					last = err2
				}
				continue
			}
		}
		if in.Rcode != dns.RcodeSuccess {
			last = errors.New(dns.RcodeToString[in.Rcode])
			continue
		}
		var out []net.IP
		for _, rr := range in.Answer {
			switch a := rr.(type) {
			case *dns.A:
				if qtype == dns.TypeA {
					out = append(out, a.A)
				}
			case *dns.AAAA:
				if qtype == dns.TypeAAAA {
					out = append(out, a.AAAA)
				}
			case *dns.CNAME:
				return r.lookupOne(ctx, strings.TrimSuffix(a.Target, "."), qtype, depth+1)
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	if last == nil {
		last = errors.New("no answer")
	}
	return nil, last
}

func (r *Resolver) LookupAll(ctx context.Context, host string) ([]net.IP, []net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			return []net.IP{ip}, nil, nil
		}
		return nil, []net.IP{ip}, nil
	}
	a, _ := r.lookupOne(ctx, host, dns.TypeA, 0)
	aaaa, err6 := r.lookupOne(ctx, host, dns.TypeAAAA, 0)
	if len(a) == 0 && len(aaaa) == 0 {
		if err6 != nil {
			return nil, nil, err6
		}
		return nil, nil, errors.New("no records")
	}
	return a, aaaa, nil
}
