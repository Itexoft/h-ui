package dnsresolver

import (
        "context"
        "fmt"
        "math/rand"
        "net"
        "net/http"
        "os"
        "strings"
        "sync"
        "time"

        "github.com/miekg/dns"
        "github.com/sirupsen/logrus"
)

type Options struct {
        Servers  []string
        Timeout  time.Duration
        IPv4Only bool
        IPv6Only bool
}

type Resolver struct {
        servers []string
        timeout time.Duration
        v4      bool
        v6      bool
        client  *http.Client
}

func New(opts Options) *Resolver {
        if len(opts.Servers) == 0 {
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
                opts.Servers = servers
        }
        if opts.Timeout == 0 {
                opts.Timeout = 2 * time.Second
        }
        if os.Getenv("HUI_DNS_IPV4_ONLY") == "true" {
                opts.IPv4Only = true
        }
        if os.Getenv("HUI_DNS_IPV6_ONLY") == "true" {
                opts.IPv6Only = true
        }
        r := &Resolver{servers: opts.Servers, timeout: opts.Timeout, v4: !opts.IPv6Only, v6: !opts.IPv4Only}
        rand.Seed(time.Now().UnixNano())
        tr := &http.Transport{
                Proxy: http.ProxyFromEnvironment,
                DialContext: r.dialContext,
                TLSHandshakeTimeout:   10 * time.Second,
                ExpectContinueTimeout: 1 * time.Second,
                IdleConnTimeout:       90 * time.Second,
                MaxIdleConns:          100,
                ForceAttemptHTTP2:     true,
        }
        r.client = &http.Client{Transport: tr, Timeout: 15 * time.Second}
        return r
}

func (r *Resolver) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
        host, port, err := net.SplitHostPort(address)
        if err != nil {
                return nil, err
        }
        ips, err := r.LookupHost(ctx, host)
        if err != nil {
                return nil, err
        }
        var d net.Dialer
        for _, ip := range ips {
                conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
                if err == nil {
                        return conn, nil
                }
        }
        if len(ips) > 0 {
                return nil, err
        }
        return nil, fmt.Errorf("no route to host")
}

func (r *Resolver) query(ctx context.Context, host string, qtype uint16) (outcome) {
        out := outcome{status: "error", transport: "udp"}
        for _, srv := range r.servers {
                m := new(dns.Msg)
                m.Id = dns.Id()
                m.RecursionDesired = true
                m.Question = []dns.Question{{Name: dns.Fqdn(host), Qtype: qtype, Qclass: dns.ClassINET}}
                c := &dns.Client{Net: "udp", Timeout: r.timeout}
                in, _, err := c.ExchangeContext(ctx, m, srv)
                if err != nil {
                        out.status = "timeout"
                } else {
                        out.status = dns.RcodeToString[in.Rcode]
                        if in.Rcode == dns.RcodeSuccess {
                                for _, ans := range in.Answer {
                                        switch rr := ans.(type) {
                                        case *dns.A:
                                                if qtype == dns.TypeA && rr.A != nil {
                                                        out.ips = append(out.ips, rr.A)
                                                }
                                        case *dns.AAAA:
                                                if qtype == dns.TypeAAAA && rr.AAAA != nil {
                                                        out.ips = append(out.ips, rr.AAAA)
                                                }
                                        }
                                }
                                if len(out.ips) > 0 {
                                        out.status = "NOERROR"
                                        return out
                                }
                        } else if in.Rcode == dns.RcodeNameError {
                                out.status = "NXDOMAIN"
                                return out
                        } else if in.Rcode != dns.RcodeServerFailure && in.Rcode != dns.RcodeRefused && in.Rcode != dns.RcodeFormatError && !in.Truncated {
                                continue
                        }
                }
                needTCP := err != nil || in == nil || in.Rcode == dns.RcodeServerFailure || in.Rcode == dns.RcodeRefused || in.Rcode == dns.RcodeFormatError || (in != nil && in.Truncated)
                if needTCP {
                        c = &dns.Client{Net: "tcp", Timeout: r.timeout}
                        in, _, err = c.ExchangeContext(ctx, m, srv)
                        out.transport = "udp->tcp"
                        if err != nil {
                                out.status = "timeout"
                        } else {
                                out.status = dns.RcodeToString[in.Rcode]
                                if in.Rcode == dns.RcodeSuccess {
                                        for _, ans := range in.Answer {
                                                switch rr := ans.(type) {
                                                case *dns.A:
                                                        if qtype == dns.TypeA && rr.A != nil {
                                                                out.ips = append(out.ips, rr.A)
                                                        }
                                                case *dns.AAAA:
                                                        if qtype == dns.TypeAAAA && rr.AAAA != nil {
                                                                out.ips = append(out.ips, rr.AAAA)
                                                        }
                                                }
                                        }
                                        if len(out.ips) > 0 {
                                                out.status = "NOERROR"
                                                return out
                                        }
                                } else if in.Rcode == dns.RcodeNameError {
                                        out.status = "NXDOMAIN"
                                        return out
                                }
                        }
                }
        }
        if len(out.ips) > 0 {
                out.status = "NOERROR"
        }
        return out
}

type outcome struct {
        ips       []net.IP
        status    string
        transport string
}

func (r *Resolver) LookupHost(ctx context.Context, host string) ([]net.IP, error) {
        start := time.Now()
        types := []uint16{}
        if r.v4 {
                types = append(types, dns.TypeA)
        }
        if r.v6 {
                types = append(types, dns.TypeAAAA)
        }
        res := make(map[uint16]outcome)
        var wg sync.WaitGroup
        var mu sync.Mutex
        for _, t := range types {
                wg.Add(1)
                go func(qt uint16) {
                        defer wg.Done()
                        o := r.query(ctx, host, qt)
                        mu.Lock()
                        res[qt] = o
                        mu.Unlock()
                }(t)
        }
        wg.Wait()
        dedup := map[string]net.IP{}
        for _, o := range res {
                for _, ip := range o.ips {
                        dedup[ip.String()] = ip
                }
        }
        ips := make([]net.IP, 0, len(dedup))
        for _, ip := range dedup {
                ips = append(ips, ip)
        }
        rand.Shuffle(len(ips), func(i, j int) { ips[i], ips[j] = ips[j], ips[i] })
        elapsed := time.Since(start)
        transport := "udp"
        for _, o := range res {
                if o.transport == "udp->tcp" {
                        transport = "udp->tcp"
                        break
                }
        }
        fields := logrus.Fields{
                "host":      host,
                "ns":        strings.Join(r.servers, ","),
                "q":         typesToString(types),
                "edns":      "off",
                "transport": transport,
                "elapsed":   fmt.Sprintf("%dms", elapsed.Milliseconds()),
        }
        if r.v4 {
                a := res[dns.TypeA]
                fields["resultA"] = a.status
                if len(a.ips) > 0 {
                        fields["ips4"] = joinIPs(a.ips)
                }
        }
        if r.v6 {
                a6 := res[dns.TypeAAAA]
                fields["resultAAAA"] = a6.status
                if len(a6.ips) > 0 {
                        fields["ips6"] = joinIPs(a6.ips)
                }
        }
        logrus.WithFields(fields).Info("dns resolve")
        if len(ips) > 0 {
                return ips, nil
        }
        parts := []string{}
        if r.v4 {
                a := res[dns.TypeA]
                parts = append(parts, fmt.Sprintf("A: %s via %s", a.status, a.transport))
        }
        if r.v6 {
                a6 := res[dns.TypeAAAA]
                parts = append(parts, fmt.Sprintf("AAAA: %s via %s", a6.status, a6.transport))
        }
        return nil, fmt.Errorf("dns: no %s results for %s (%s)", typesLabel(types), host, strings.Join(parts, "; "))
}

func typesToString(ts []uint16) string {
        names := make([]string, len(ts))
        for i, t := range ts {
                names[i] = dns.TypeToString[t]
        }
        return strings.Join(names, ",")
}

func joinIPs(ips []net.IP) string {
        s := make([]string, len(ips))
        for i, ip := range ips {
                s[i] = ip.String()
        }
        return strings.Join(s, " ")
}

func typesLabel(ts []uint16) string {
        names := make([]string, len(ts))
        for i, t := range ts {
                if t == dns.TypeA {
                        names[i] = "A"
                } else {
                        names[i] = "AAAA"
                }
        }
        return strings.Join(names, "/")
}

func (r *Resolver) HTTPClient() *http.Client {
        return r.client
}

func (r *Resolver) AsNetResolver() *net.Resolver {
        return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
                d := net.Dialer{Timeout: r.timeout}
                return d.DialContext(ctx, network, r.servers[0])
        }}
}

var Default = New(Options{})

