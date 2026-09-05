package firewall

import (
	"net"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
)

func isolationSite(t *testing.T) model.Site {
	t.Helper()
	c := model.ConfigFromSite(model.NewDefaultSite("isolation", "age1example"))
	enabled := true
	c.Modules.AirVPN = &model.AirVPNModuleConfig{Enabled: &enabled, Servers: "europe"}
	c.Modules.Arr = &model.ArrModuleConfig{Enabled: &enabled, Network: model.ModuleNetworkAirVPN}
	c.Modules.TailnetRouter = &model.TailnetRouterConfig{Enabled: &enabled}
	s, _, err := modules.Compose(c)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestARRMatchesPublicDestinationRatherThanVPNNextHop(t *testing.T) {
	p, err := PlanFromSite(isolationSite(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range p.Rules {
		if r.Name == "ARR media acquisition through AirVPN" {
			if r.DestinationCIDR != "0.0.0.0/0" || r.Route != "airvpn" || r.SourceMAC == "" {
				t.Fatalf("ARR forwarding rule: %#v", r)
			}
			return
		}
	}
	t.Fatal("missing ARR egress rule")
}

func TestMandatoryIsolationPrecedesConnectionState(t *testing.T) {
	p, err := PlanFromSiteWithAirVPN(isolationSite(t), AirVPNProfile{EndpointHost: "vpn.example", EndpointPort: 1637, TunnelAddress: "10.1.2.3", SHA256: strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	rules, err := RenderNFTWithResolver(p, func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("8.8.4.4")}, nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, chain := range []string{"input", "forward"} {
		start := strings.Index(rules, "  chain "+chain+" {")
		part := rules[start:]
		guard := strings.Index(part, "jump restricted_"+chain)
		state := strings.Index(part, "ct state established,related accept")
		if guard < 0 || guard > state {
			t.Fatalf("%s accepts stale connections before isolation", chain)
		}
	}
	if !strings.Contains(rules, "192.168.0.0/16") || !strings.Contains(rules, "iifname \"sandbox0\" ip daddr @non_public_v4") {
		t.Fatal("SANDBOX lacks HOME/non-public destination denial")
	}
}

func TestSelectedAirVPNClientCanRenewItsServersDHCPLease(t *testing.T) {
	p, err := PlanFromSiteWithAirVPN(isolationSite(t), AirVPNProfile{EndpointHost: "vpn.example", EndpointPort: 1637, TunnelAddress: "10.1.2.3", SHA256: strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	rules, err := RenderNFTWithResolver(p, func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("8.8.4.4")}, nil })
	if err != nil {
		t.Fatal(err)
	}
	allow := `iifname "servers0" ip saddr @airvpn_sources ip daddr 10.10.20.1 udp sport 68 udp dport 67 return`
	drop := `ip saddr @airvpn_sources drop`
	if strings.Index(rules, allow) < 0 || strings.Index(rules, allow) > strings.Index(rules, drop) {
		t.Fatalf("selected-client DHCP renewal is not allowed before the deny: %s", rules)
	}
}
