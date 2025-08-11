package dnsinit

import (
	"context"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

func envBool(k string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(k)))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func envStr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func init() {
	if os.Getenv("HUI_DNS_PREFER_GO") == "" &&
		os.Getenv("HUI_DNS_TRANSPORT") == "" &&
		os.Getenv("HUI_DNS_IPV4_ONLY") == "" &&
		os.Getenv("HUI_DNS_TIMEOUT") == "" &&
		os.Getenv("HUI_DNS_STRICT_ERRORS") == "" {
		return
	}

	preferGo := envBool("HUI_DNS_PREFER_GO")
	strict := envBool("HUI_DNS_STRICT_ERRORS")
	transport := strings.ToLower(envStr("HUI_DNS_TRANSPORT", ""))
	ipv4Only := envBool("HUI_DNS_IPV4_ONLY")
	timeout := 2 * time.Second
	if t := envStr("HUI_DNS_TIMEOUT", ""); t != "" {
		if d, err := time.ParseDuration(t); err == nil {
			timeout = d
		}
	}

	pg := preferGo || transport != "" || ipv4Only
	net.DefaultResolver = &net.Resolver{
		PreferGo:     pg,
		StrictErrors: strict,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			netw := network
			switch transport {
			case "tcp":
				netw = "tcp"
			case "udp":
				netw = "udp"
			}
			if ipv4Only {
				if strings.HasPrefix(netw, "tcp") {
					netw = "tcp4"
				} else {
					netw = "udp4"
				}
			}
			d := &net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, netw, address)
		},
	}

	if envBool("HUI_DNS_DEBUG") {
		log.Printf("dns resolver prefer_go=%v transport=%s ipv4_only=%v strict_errors=%v timeout=%s", pg, transport, ipv4Only, strict, timeout)
	}
}
