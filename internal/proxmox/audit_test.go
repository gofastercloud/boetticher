package proxmox

import (
	"context"
	"net/http"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestClassifyGuestsKeepsUnknownGuestsInformational(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	audits := ClassifyGuests(plan, []GuestSummary{
		{VMID: model.ProxmoxVMID, Name: "lab-fw-01", Kind: KindQEMU, Status: "running"},
		{VMID: model.DNS01VMID, Name: "lab-dns-01", Kind: KindLXC, Status: "running"},
		{VMID: 550, Name: "user-vm-550", Kind: KindQEMU, Status: "running"},
	})
	var foundUnknown bool
	for _, audit := range audits {
		if audit.VMID != 550 {
			continue
		}
		foundUnknown = true
		if audit.Result != "INFO" || audit.Ownership != UserOwnership {
			t.Fatalf("unexpected unknown guest audit: %#v", audit)
		}
	}
	if !foundUnknown {
		t.Fatal("unknown user guest was not reported")
	}
}

func TestClassifyGuestsDetectsOwnedDrift(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	audits := ClassifyGuests(plan, []GuestSummary{
		{VMID: model.ProxmoxVMID, Name: "renamed-firewall", Kind: KindQEMU, Status: "running"},
	})
	for _, audit := range audits {
		if audit.VMID == model.ProxmoxVMID {
			if audit.Result != "DRIFT" {
				t.Fatalf("owned rename was not detected: %#v", audit)
			}
			return
		}
	}
	t.Fatal("firewall audit was absent")
}

func TestClassifyBuilderRequiresCanonicalIdentityAndOwnership(t *testing.T) {
	owned := classifyBuilder(map[string]any{
		"name": "lab-builder-01", "status": "stopped", "tags": "boetticher;managed;boetticher-builder",
	})
	if !owned.Exists || !owned.Owned || owned.Name != "lab-builder-01" {
		t.Fatalf("canonical builder was not recognized: %#v", owned)
	}
	for _, current := range []map[string]any{
		{"name": "lab-builder-01", "tags": "boetticher;managed"},
		{"name": "user-vm-190", "tags": "user"},
	} {
		classified := classifyBuilder(current)
		if !classified.Exists || classified.Owned {
			t.Fatalf("unowned VMID 190 was accepted as the builder: %#v", classified)
		}
	}
}

func TestInspectBuilderHoldsForWrongGuestKind(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		switch r.URL.Path {
		case "/api2/json/nodes/lab-proxmox-01/qemu/190/config":
			return apiResponse(404, `{"errors":{"vmid":"not found"}}`)
		case "/api2/json/nodes/lab-proxmox-01/lxc/190/config":
			return apiResponse(200, `{"data":{"hostname":"user-lxc-190","status":"stopped","tags":"user"}}`)
		default:
			t.Fatalf("unexpected builder inspection request: %s", r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	audit, err := InspectBuilder(context.Background(), client, "lab-proxmox-01")
	if err != nil {
		t.Fatal(err)
	}
	if !audit.Exists || audit.Owned || audit.Name != "lxc guest at VMID 190" {
		t.Fatalf("wrong-kind builder collision was not held: %#v", audit)
	}
}
