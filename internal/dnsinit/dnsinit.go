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
	debug := envBool("HUI_DNS_DEBUG")
	preferGo := envBool("HUI_DNS_PREFER_GO")
	transport := strings.ToLower(envStr("HUI_DNS_TRANSPORT", ""))
	ipv4Only := envBool("HUI_DNS_IPV4_ONLY")
	timeoutVar := envStr("HUI_DNS_TIMEOUT", "")
	strictVar := envStr("HUI_DNS_STRICT_ERRORS", "")
	timeout := 2 * time.Second
	if timeoutVar != "" {
		if d, err := time.ParseDuration(timeoutVar); err == nil {
			timeout = d
		}
	}
	strict := envBool("HUI_DNS_STRICT_ERRORS")
	if !preferGo && transport == "" && !ipv4Only && timeoutVar == "" && strictVar == "" {
		if debug {
			log.Printf("dns resolver prefer_go=%v transport=%s ipv4_only=%v strict_errors=%v timeout=%s", false, "", false, false, timeout)
		}
		return
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
	if debug {
		log.Printf("dns resolver prefer_go=%v transport=%s ipv4_only=%v strict_errors=%v timeout=%s", pg, transport, ipv4Only, strict, timeout)
	}
}
