package proxmox

import (
	"testing"

	"github.com/dave/labinabox/internal/model"
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
