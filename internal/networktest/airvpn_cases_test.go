package networktest

import "testing"

func TestAirVPNChecksSeparatePublicSuccessFromHOMEAndDNSBypasses(t *testing.T) {
	cases := AirVPNChecks("192.168.4.5", "lab.home.arpa", []string{"10.10.10.10"}, []string{"https://cloudflare-dns.com/dns-query", "https://dns.google/dns-query"})
	byName := map[string]AirVPNCheck{}
	for _, c := range cases {
		byName[c.Name] = c
	}
	for _, name := range []string{"home-22", "home-53", "home-443", "direct-core-dns-10.10.10.10", "direct-core-authoritative-10.10.10.10", "upstream-doh-cloudflare-dns.com", "upstream-doh-dns.google", "external-dns-1.1.1.1-853"} {
		c, ok := byName[name]
		if !ok || c.Allowed {
			t.Fatalf("missing deny check %s", name)
		}
	}
	for _, name := range []string{"public-internet", "private-dns-via-router", "public-dns-via-router", "router-ntp"} {
		c, ok := byName[name]
		if !ok || !c.Allowed {
			t.Fatalf("missing independent allow check %s", name)
		}
	}
}
