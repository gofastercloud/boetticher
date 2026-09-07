package firewallmodule

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gofastercloud/boetticher/internal/openwrt"
	"github.com/gofastercloud/boetticher/internal/proxmox"
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

func CheckHealth(ctx context.Context, client *proxmox.Client, node string, desired DesiredState, provider *openwrt.Client) (FirewallHealth, error) {
	health := FirewallHealth{GatewaysExpected: len(desired.Zones)}
	status, err := ReadStatus(ctx, client, node, desired)
	if err != nil {
		return health, err
	}
	health.Provider = status
	if !status.Exists {
		return health, nil
	}
	if provider == nil {
		return health, fmt.Errorf("provider client is required for firewall health")
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
	health.FirewallActive, err = provider.ServiceRunning(ctx, "firewall")
	if err != nil {
		return health, err
	}
	if !health.FirewallActive {
		health.FirewallActive, err = provider.ServiceRunning(ctx, "firewall4")
		if err != nil {
			return health, err
		}
	}
	health.HOMEDefaultRoute, err = openwrt.DefaultRouteActive(runtime)
	if err != nil {
		return health, err
	}
	return health, nil
}

func GatewayCount(runtime json.RawMessage, desired DesiredState) int {
	count := 0
	for _, zone := range desired.Zones {
		if bytes.Contains(runtime, []byte("boetticher_iface_"+strings.ToLower(zone.Name))) {
			count++
		}
	}
	return count
}

func verificationLabel(value bool) string {
	if value {
		return "verified"
	}
	return "not verified"
}
