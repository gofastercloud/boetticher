package firewallmodule

import (
	"encoding/json"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestGatewayCountAndFirewallHealthAreCoarseAndTruthful(t *testing.T) {
	desired, err := DesiredFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	if err != nil {
		t.Fatal(err)
	}
	runtime := json.RawMessage(`{"interface":[{"interface":"boetticher_iface_transit"},{"interface":"boetticher_iface_infra"},{"interface":"boetticher_iface_servers"},{"interface":"boetticher_iface_trusted"},{"interface":"boetticher_iface_sandbox"},{"interface":"boetticher_iface_mgmt"}]}`)
	if got := GatewayCount(runtime, desired); got != 6 {
		t.Fatalf("gateway count = %d, want 6", got)
	}
	health := FirewallHealth{Provider: Status{Exists: true, Running: true, OwnershipProven: true, NetworkShapeOK: true, StorageIdentity: true}, APIReachable: true, GatewaysPresent: 6, GatewaysExpected: 6, FirewallActive: true, HOMEDefaultRoute: true}
	if !health.Healthy() {
		t.Fatalf("healthy facts were rejected: %s", health.Detail())
	}
	health.HOMEDefaultRoute = false
	if health.Healthy() {
		t.Fatal("missing HOME route was reported healthy")
	}
}
