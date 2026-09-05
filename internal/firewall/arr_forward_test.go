package firewall

import (
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
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
			if rule.From != "TRANSIT" || rule.To != "SERVERS" || rule.SourceCIDR != model.AirVPNGuestAddress+"/32" || rule.DestinationCIDR != model.ArrGuestAddress+"/32" || rule.Protocol != "tcp/udp" || strings.Join(rule.Ports, ",") != "45678" || rule.NAT {
				t.Fatalf("forwarded peer rule is too broad: %#v", rule)
			}
		}
		if found != enabled {
			t.Fatalf("forwarding present=%v for ARR enabled=%v", found, enabled)
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
