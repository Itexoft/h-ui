package main

import (
	"context"
	"net"
	"os"
	"strings"
	"time"
)

func init() {
	preferGo := os.Getenv("HUI_DNS_PREFER_GO") == "1"
	forceTCP := os.Getenv("HUI_DNS_FORCE_TCP") == "1"
	ipv4Only := os.Getenv("HUI_DNS_IPV4_ONLY") == "1"

	if preferGo || forceTCP || ipv4Only {
		d := &net.Dialer{Timeout: 2 * time.Second}
		net.DefaultResolver = &net.Resolver{
			PreferGo: preferGo,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				if forceTCP {
					if strings.HasPrefix(network, "udp") {
						network = "tcp" + network[len("udp"):]
					}
					if network == "tcp" && ipv4Only {
						network = "tcp4"
					}
				} else if ipv4Only {
					if strings.HasPrefix(network, "udp") {
						network = "udp4"
					} else if strings.HasPrefix(network, "tcp") {
						network = "tcp4"
					}
				}
				return d.DialContext(ctx, network, address)
			},
		}
	}
}
