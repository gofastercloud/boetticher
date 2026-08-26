package opnsense

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestPlanIsDeterministicAndUsesReservationOnlyMGMT(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	first, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	second, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	left, _ := json.Marshal(first)
	right, _ := json.Marshal(second)
	if string(left) != string(right) || !reflect.DeepEqual(first, second) {
		t.Fatal("identical sites generated different OPNsense plans")
	}
	for _, zone := range first.Zones {
		if zone.Name == "MGMT" && zone.Pool != "" {
			t.Fatal("MGMT must not have a dynamic DHCP pool")
		}
		if zone.Name != "MGMT" && zone.Pool == "" {
			t.Fatalf("zone %s has no deterministic DHCP pool", zone.Name)
		}
	}
}

func TestKeaPayloadHasNormalGatewayOptions(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	payloads := plan.KeaPayloads()
	if len(payloads) != 4 {
		t.Fatalf("got %d Kea payloads", len(payloads))
	}
	if got := payloads[0].Subnet4.OptionData.Routers; got != "10.10.10.1" {
		t.Fatalf("TRUSTED router = %q", got)
	}
	if len(payloads[3].Subnet4.Pools) != 0 {
		t.Fatal("MGMT unexpectedly has a pool")
	}
}

func TestKeaPayloadHasPerZoneDDNSContractWithoutEmbeddingSecretsInDesiredState(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	payloads := plan.KeaPayloads()
	if payloads[0].Subnet4.DDNSForwardZone == "" || payloads[0].Subnet4.DDNSReverseZone == "" || payloads[0].Subnet4.DDNSDNSServer != "10.10.20.10" {
		t.Fatalf("missing DDNS subnet contract: %#v", payloads[0])
	}
	if payloads[0].Subnet4.DDNSDomainKeySecret != "" {
		t.Fatal("desired Kea payload embedded a TSIG secret")
	}
	withSecret := plan.KeaPayloadsWithTSIG("c2VjcmV0")
	if withSecret[0].Subnet4.DDNSDomainKeySecret != "c2VjcmV0" {
		t.Fatal("runtime TSIG was not added to the apply payload")
	}
}

func TestDDNSPayloadEnablesManagedD2WithoutSecrets(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	payload := plan.DDNSPayload()
	ddns, ok := payload["ddns"].(map[string]any)
	if !ok {
		t.Fatalf("unexpected DDNS payload: %#v", payload)
	}
	general, ok := ddns["general"].(map[string]any)
	if !ok || general["enabled"] != "1" || general["server_ip"] != "127.0.0.1" || general["server_port"] != "53001" {
		t.Fatalf("unexpected D2 general payload: %#v", payload)
	}
	encoded, _ := json.Marshal(payload)
	if string(encoded) != `{"ddns":{"general":{"enabled":"1","manual_config":"0","server_ip":"127.0.0.1","server_port":"53001"}}}` {
		t.Fatalf("DDNS payload is not deterministic: %s", encoded)
	}
}
