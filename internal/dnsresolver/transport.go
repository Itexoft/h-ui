package dnsresolver

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

var once sync.Map

func NewTransport(r *Resolver, host string) *http.Transport {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			a, aaaa, err := r.LookupAll(ctx, host)
			if err != nil {
				return nil, err
			}
			ips := append([]net.IP{}, a...)
			ips = append(ips, aaaa...)
			var last error
			for _, ip := range ips {
				c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
				if err == nil {
					if _, ok := once.Load(host); !ok {
						logrus.Infof("dns host=%s servers=%v a=%v aaaa=%v ip=%s", host, r.servers, a, aaaa, ip)
						once.Store(host, true)
					}
					return c, nil
				}
				last = err
			}
			return nil, last
		},
		TLSClientConfig:       &tls.Config{ServerName: host},
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          100,
		ForceAttemptHTTP2:     true,
	}
	return tr
}
