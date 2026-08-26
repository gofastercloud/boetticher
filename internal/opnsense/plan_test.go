package opnsense

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/dave/labinabox/internal/model"
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
