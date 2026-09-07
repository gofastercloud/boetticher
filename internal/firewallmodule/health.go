package firewallmodule

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/gofastercloud/boetticher/internal/openwrt"
)

// FirewallHealth is the shared coarse operational result consumed by CLI
// status and Controller display integrations. It is not packet qualification.
type FirewallHealth struct {
	Provider         Status
	APIReachable     bool
	GatewaysPresent  int
	GatewaysExpected int
	FirewallActive   bool
	HOMEDefaultRoute bool
}

func (h FirewallHealth) Healthy() bool {
	return h.Provider.Exists && h.Provider.Running && h.Provider.OwnershipProven && h.Provider.NetworkShapeOK && h.Provider.StorageIdentity && h.APIReachable && h.GatewaysPresent == h.GatewaysExpected && h.FirewallActive && h.HOMEDefaultRoute
}

func (h FirewallHealth) Detail() string {
	return fmt.Sprintf("provider=%s, API=%s, gateways=%d/%d, firewall=%s, HOME route=%s", ProviderSummary(h.Provider), verificationLabel(h.APIReachable), h.GatewaysPresent, h.GatewaysExpected, verificationLabel(h.FirewallActive), verificationLabel(h.HOMEDefaultRoute))
}

// CheckHealthViaSSH is the installed-Controller path. Host configuration is
// authoritative in /etc/boetticher/lab.yml, so this uses the same strict Host
// transport as host status and does not require a private site repository or a
// second Proxmox API credential.
func CheckHealthViaSSH(ctx context.Context, host HostClient, desired DesiredState, provider *openwrt.Client) (FirewallHealth, error) {
	health := FirewallHealth{GatewaysExpected: len(desired.Zones)}
	observed, err := InspectHostProvider(ctx, host)
	if err != nil {
		return health, err
	}
	if !observed.Exists {
		return health, nil
	}
	if observed.Kind != "qemu" {
		return health, fmt.Errorf("provider VMID %d is %s, expected qemu", ProviderVMID, observed.Kind)
	}
	if err := validateHostProvider(observed, "boetticher-data"); err != nil {
		return health, err
	}
	health.Provider = Status{Exists: true, Running: observed.Running, Name: ProviderName, OwnershipProven: true, NetworkShapeOK: true, StorageIdentity: true}
	if provider == nil {
		return health, errors.New("provider client is required for firewall health")
	}
	if err := provider.Authenticate(ctx); err != nil {
		return health, err
	}
	health.APIReachable = true
	runtime, err := provider.InterfaceDump(ctx)
	if err != nil {
		return health, err
	}
	health.GatewaysPresent = GatewayCount(runtime, desired)
	health.FirewallActive, err = FirewallRuntimeActiveViaHost(ctx, host)
	if err != nil {
		return health, err
	}
	health.HOMEDefaultRoute, err = openwrt.DefaultRouteVia(runtime, desired.ManagementGateway)
	if err != nil {
		return health, err
	}
	return health, nil
}

func GatewayCount(runtime json.RawMessage, desired DesiredState) int {
	var payload any
	if json.Unmarshal(runtime, &payload) != nil {
		return 0
	}
	count := 0
	for _, zone := range desired.Zones {
		if interfaceReady(payload, "boetticher_iface_"+strings.ToLower(zone.Name), zone.Gateway) {
			count++
		}
	}
	return count
}

func interfaceReady(value any, wantedName, wantedAddress string) bool {
	switch typed := value.(type) {
	case map[string]any:
		name, _ := typed["interface"].(string)
		up, _ := typed["up"].(bool)
		if name == wantedName && up {
			addresses, _ := typed["ipv4-address"].([]any)
			for _, item := range addresses {
				address, _ := item.(map[string]any)
				if address["address"] == wantedAddress && address["mask"] == float64(24) {
					return true
				}
			}
		}
		for _, item := range typed {
			if interfaceReady(item, wantedName, wantedAddress) {
				return true
			}
		}
	case []any:
		for _, item := range typed {
			if interfaceReady(item, wantedName, wantedAddress) {
				return true
			}
		}
	}
	return false
}

func verificationLabel(value bool) string {
	if value {
		return "verified"
	}
	return "not verified"
}
