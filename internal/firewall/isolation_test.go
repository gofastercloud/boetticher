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
	c.Modules.TailnetRouter = &model.TailnetRouterConfig{Enabled: &enabled}
	s, _, err := modules.Compose(c)
	if err != nil {
		t.Fatal(err)
	}
	return s
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

func TestRenderedIsolationRulesCarryOwnershipComments(t *testing.T) {
	tests := []struct {
		name string
		plan Plan
	}{
		{
			name: "default",
			plan: func() Plan {
				plan, err := PlanFromSite(model.NewDefaultSite("default", "age1example"))
				if err != nil {
					t.Fatal(err)
				}
				return plan
			}(),
		},
		{
			name: "airvpn",
			plan: func() Plan {
				plan, err := PlanFromSiteWithAirVPN(isolationSite(t), AirVPNProfile{EndpointHost: "vpn.example", EndpointPort: 1637, TunnelAddress: "10.1.2.3", SHA256: strings.Repeat("a", 64)})
				if err != nil {
					t.Fatal(err)
				}
				return plan
			}(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rules, err := RenderNFTWithResolver(test.plan, func(string) ([]net.IP, error) {
				return []net.IP{net.ParseIP("8.8.4.4")}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(rules, "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "type ") || strings.HasPrefix(trimmed, "policy ") || strings.HasPrefix(trimmed, "chain ") {
					continue
				}
				if !strings.Contains(line, " accept") && !strings.Contains(line, " drop") && !strings.Contains(line, " return") && !strings.Contains(line, " jump ") {
					continue
				}
				if !strings.Contains(line, `comment "boetticher:`) {
					t.Fatalf("owned isolation rule has no ownership comment: %s", line)
				}
			}
		})
	}
}
