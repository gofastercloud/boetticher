package networktest

import (
	"net"
	"net/url"
	"sort"
	"strconv"
)

type AirVPNCheck struct {
	Name       string
	Target     string
	Port       int
	Kind       string
	Query      string
	URL        string
	ServerName string
	Allowed    bool
}

// AirVPNChecks keeps HOME, resolver bypass and application egress independent.
// Callers repeat deny checks across each lifecycle/fault stage.
func AirVPNChecks(home, domain string, primaryDNS, upstreams []string) []AirVPNCheck {
	checks := []AirVPNCheck{
		{Name: "public-internet", Kind: "http", URL: "https://api.ipify.org", Allowed: true},
		{Name: "private-dns-via-router", Kind: "dns", Target: "10.10.5.20", Port: 53, Query: "monitor." + domain, Allowed: true},
		{Name: "public-dns-via-router", Kind: "dns", Target: "10.10.5.20", Port: 53, Query: "example.com", Allowed: true},
		{Name: "router-ntp", Kind: "ntp", Target: "10.10.5.20", Port: 123, Allowed: true},
	}
	if net.ParseIP(home) != nil {
		for _, port := range []int{22, 53, 80, 443, 8006} {
			checks = append(checks, AirVPNCheck{Name: "home-" + strconv.Itoa(port), Kind: "tcp", Target: home, Port: port})
		}
	}
	for _, address := range primaryDNS {
		checks = append(checks, AirVPNCheck{Name: "direct-core-dns-tcp-" + address, Kind: "tcp", Target: address, Port: 53})
		checks = append(checks, AirVPNCheck{Name: "direct-core-dns-" + address, Kind: "dns", Target: address, Port: 53, Query: "example.com"})
		checks = append(checks, AirVPNCheck{Name: "direct-core-authoritative-" + address, Kind: "tcp", Target: address, Port: 5353})
		checks = append(checks, AirVPNCheck{Name: "direct-core-ntp-" + address, Kind: "ntp", Target: address, Port: 123})
	}
	for _, address := range []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"} {
		checks = append(checks, AirVPNCheck{Name: "external-dns-udp-" + address, Kind: "dns", Target: address, Port: 53, Query: "example.com"})
		for _, port := range []int{53, 853} {
			checks = append(checks, AirVPNCheck{Name: "external-dns-" + address + "-" + strconv.Itoa(port), Kind: "tcp", Target: address, Port: port})
		}
	}
	for _, endpoint := range upstreams {
		parsed, err := url.Parse(endpoint)
		if err == nil && parsed.Hostname() != "" {
			checks = append(checks, AirVPNCheck{Name: "upstream-doh-" + parsed.Hostname(), Kind: "tcp", Target: parsed.Hostname(), Port: 443})
		}
	}
	sort.Slice(checks, func(i, j int) bool { return checks[i].Name < checks[j].Name })
	return checks
}
