package dns

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

type NoEDNSResolver struct {
	servers []string
	timeout time.Duration
	network string
}

func NewNoEDNSResolver() *NoEDNSResolver {
	return &NoEDNSResolver{
		servers: []string{"127.0.0.1:53", "[::1]:53"},
		timeout: 2 * time.Second,
		network: "udp",
	}
}

func (r *NoEDNSResolver) exchangeNoEDNS(ctx context.Context, qname string, qtype uint16, netw, server string) (*dns.Msg, error) {
	q := new(dns.Msg)
	q.Id = dns.Id()
	q.RecursionDesired = true
	q.Question = []dns.Question{{
		Name:   dns.Fqdn(qname),
		Qtype:  qtype,
		Qclass: dns.ClassINET,
	}}
	c := &dns.Client{Net: netw, Timeout: r.timeout, SingleInflight: true}
	in, _, err := c.ExchangeContext(ctx, q, server)
	return in, err
}
func (r *NoEDNSResolver) lookupQtype(ctx context.Context, name string, qtype uint16) (net.IP, error) {
	const maxCNAME = 10
	current := name
	for hop := 0; hop < maxCNAME; hop++ {
		var nextCNAME string
		for _, srv := range r.servers {
			in, _ := r.exchangeNoEDNS(ctx, current, qtype, "udp", srv)
			if ip, cname := pickAnswer(in, qtype); ip != nil {
				return ip, nil
			} else if cname != "" {
				nextCNAME = cname
				continue
			}
			if in == nil || in.Rcode != dns.RcodeSuccess || len(in.Answer) == 0 || in.Truncated {
				if inTCP, _ := r.exchangeNoEDNS(ctx, current, qtype, "tcp", srv); inTCP != nil {
					if ip, cname := pickAnswer(inTCP, qtype); ip != nil {
						return ip, nil
					} else if cname != "" {
						nextCNAME = cname
						continue
					}
				}
			}
		}
		if nextCNAME == "" {
			break
		}
		current = dns.Fqdn(nextCNAME)
	}
	return nil, fmt.Errorf("no %s record for %s", dns.TypeToString[qtype], name)
}

func pickAnswer(in *dns.Msg, qtype uint16) (net.IP, string) {
	if in == nil {
		return nil, ""
	}
	for _, ans := range in.Answer {
		switch rr := ans.(type) {
		case *dns.A:
			if qtype == dns.TypeA && rr.A != nil {
				return rr.A, ""
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA && rr.AAAA != nil {
				return rr.AAAA, ""
			}
		case *dns.CNAME:
			return nil, rr.Target
		}
	}
	return nil, ""
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
