package firewall

import (
	"net"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
	networkmodel "github.com/gofastercloud/boetticher/internal/network"
)

func TestARRForwardedPortIsBoundedAndDisabledWithARR(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		config := model.ConfigFromSite(model.NewSite("arr-forward", "age1arr", model.GatewayModeManaged))
		yes := true
		config.Modules.AirVPN = &model.AirVPNModuleConfig{Enabled: &yes, Servers: "europe", QBittorrentPort: 45678}
		config.Modules.Arr = &model.ArrModuleConfig{Enabled: &enabled, Network: model.ModuleNetworkAirVPN}
		site, _, err := modules.Compose(config)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := PlanFromSite(site)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, rule := range plan.Rules {
			if rule.Counter != "boetticher_arr_forwarded_peer" {
				continue
			}
			found = true
			if rule.From != "TRANSIT" || rule.To != "SERVERS" || rule.SourceCIDR != model.AirVPNGuestAddress+"/32" || rule.SourceMAC != networkmodel.ManagedModuleMAC(model.AirVPNGuestVMID) || rule.DestinationCIDR != model.ArrGuestAddress+"/32" || rule.Protocol != "tcp/udp" || strings.Join(rule.Ports, ",") != "45678" || rule.NAT {
				t.Fatalf("forwarded peer rule is too broad: %#v", rule)
			}
		}
		if found != enabled {
			t.Fatalf("forwarding present=%v for ARR enabled=%v", found, enabled)
		}
		if !enabled {
			continue
		}
		plan, err = PlanFromSiteWithAirVPN(site, AirVPNProfile{EndpointHost: "airvpn.example", EndpointPort: 1637, TunnelAddress: "10.64.12.3", SHA256: strings.Repeat("a", 64)})
		if err != nil {
			t.Fatal(err)
		}
		plan, err = BindAirVPNEndpoint(plan, func(host string) ([]net.IP, error) {
			if host != "airvpn.example" {
				t.Fatalf("unexpected AirVPN endpoint lookup %q", host)
			}
			return []net.IP{net.ParseIP("198.51.100.44")}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		ruleset, err := RenderNFTWithResolver(plan, func(host string) ([]net.IP, error) {
			if host == "cloudflare-dns.com" || host == "dns.google" {
				return []net.IP{net.ParseIP("203.0.113.53")}, nil
			}
			if host != "airvpn.example" {
				t.Fatalf("unexpected AirVPN render lookup %q", host)
			}
			return []net.IP{net.ParseIP("198.51.100.44")}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, protocol := range []string{"tcp", "udp"} {
			want := `iifname "transit0" ether saddr ` + networkmodel.ManagedModuleMAC(model.AirVPNGuestVMID) + ` oifname "servers0" ip saddr 10.10.5.20/32 ip daddr 10.10.20.110/32 ` + protocol + ` dport 45678 counter accept`
			if !strings.Contains(ruleset, want) {
				t.Fatalf("forwarded peer %s rule is missing the AirVPN source MAC: %s", protocol, ruleset)
			}
		}
		if strings.Contains(ruleset, `iifname "transit0" oifname "servers0" ip saddr 10.10.5.20/32 ip daddr 10.10.20.110/32`) {
			t.Fatalf("forwarded peer rule is missing a source MAC: %s", ruleset)
		}
	}
}

func TestARRForwardedPortValidation(t *testing.T) {
	for _, port := range []int{-1, 22, 2048, 8080, 9696, 65536} {
		config := model.ConfigFromSite(model.NewSite("arr-forward", "age1arr", model.GatewayModeManaged))
		yes := true
		config.Modules.AirVPN = &model.AirVPNModuleConfig{Enabled: &yes, Servers: "europe", QBittorrentPort: port}
		if _, _, err := modules.Compose(config); err == nil {
			t.Fatalf("accepted port %d", port)
		}
	}
}
