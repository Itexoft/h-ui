package main

import (
	"context"
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
		os.Getenv("HUI_DNS_FORCE_TCP") == "" &&
		os.Getenv("HUI_DNS_IPV4_ONLY") == "" &&
		os.Getenv("HUI_DNS_TIMEOUT") == "" &&
		os.Getenv("HUI_DNS_STRICT_ERRORS") == "" {
		return
	}

	preferGo := envBool("HUI_DNS_PREFER_GO")
	strict := envBool("HUI_DNS_STRICT_ERRORS")

	transport := strings.ToLower(envStr("HUI_DNS_TRANSPORT", ""))
	if transport == "" && envBool("HUI_DNS_FORCE_TCP") {
		transport = "tcp"
	}
	ipv4Only := envBool("HUI_DNS_IPV4_ONLY")

	timeout := 2 * time.Second
	if t := envStr("HUI_DNS_TIMEOUT", ""); t != "" {
		if d, err := time.ParseDuration(t); err == nil {
			timeout = d
		}
	}

	net.DefaultResolver = &net.Resolver{
		PreferGo:     preferGo || transport != "" || ipv4Only,
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
}
