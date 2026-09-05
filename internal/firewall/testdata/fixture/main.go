package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/gofastercloud/boetticher/internal/firewall"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
)

func main() {
	c := model.ConfigFromSite(model.NewDefaultSite("packet-fixture", "age1example"))
	enabled := true
	c.Modules.AirVPN = &model.AirVPNModuleConfig{Enabled: &enabled, Servers: "europe"}
	c.Modules.Arr = &model.ArrModuleConfig{Enabled: &enabled, Network: model.ModuleNetworkAirVPN}
	c.Modules.Logging = &model.ToggleModuleConfig{Enabled: &enabled}
	s, _, err := modules.Compose(c)
	if err != nil {
		panic(err)
	}
	p, err := firewall.PlanFromSiteWithAirVPN(s, firewall.AirVPNProfile{EndpointHost: "vpn.example", EndpointPort: 1637, TunnelAddress: "10.174.1.2", SHA256: strings.Repeat("a", 64), EndpointAddresses: []string{"8.8.4.4"}})
	if err != nil {
		panic(err)
	}
	p.Upstream = &firewall.UpstreamObservation{Interface: "wan0", MAC: p.Interfaces[0].MAC, Address: "192.168.4.5/24", Gateway: "192.168.4.1"}
	rules, err := firewall.RenderNFTWithResolver(p, func(host string) ([]net.IP, error) {
		if host == "vpn.example" {
			return []net.IP{net.ParseIP("8.8.4.4")}, nil
		}
		return []net.IP{net.ParseIP("1.1.1.1")}, nil
	})
	if err != nil {
		panic(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"gateway": rules, "firewall_plan": p, "domain": s.Network.Domain, "firewall_non_public_ipv4": firewall.NonPublicIPv4, "logging_plan": map[string]any{"enabled": true, "collector_address": "10.10.10.40"}, "host_isolation": firewall.HostIsolationForSite(s), "trusted_lab_services": model.TrustedLabServices()}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
