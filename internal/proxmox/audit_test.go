package proxmox

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
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

func TestPurgeModuleHoldsForOppositeGuestKindAtReservedIdentity(t *testing.T) {
	plan, err := PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	var expected GuestPlan
	for _, guest := range plan.Guests {
		if guest.Owner == "boetticher/module/dns" {
			expected = guest
			break
		}
	}
	if expected.VMID == 0 {
		t.Fatal("DNS fixture guest is missing")
	}
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		qemuPath := "/api2/json/nodes/lab-proxmox-01/qemu/" + strconv.Itoa(expected.VMID) + "/config"
		lxcPath := "/api2/json/nodes/lab-proxmox-01/lxc/" + strconv.Itoa(expected.VMID) + "/config"
		switch {
		case r.Method == http.MethodGet && r.URL.Path == qemuPath:
			return response([]byte(`{"data":{"name":"user-qemu","tags":"user"}}`))
		case r.Method == http.MethodGet && r.URL.Path == lxcPath:
			t.Fatalf("purge inspected the expected LXC after finding an opposite-kind QEMU")
			return nil
		default:
			t.Fatalf("unexpected request during purge ownership check: %s %s", r.Method, r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := PurgeModule(context.Background(), client, plan, "dns"); err == nil || !strings.Contains(err.Error(), "HOLD") {
		t.Fatalf("opposite-kind purge collision was not held: %v", err)
	}
}

func TestPurgeModuleHoldsForUndeclaredPersistentVolume(t *testing.T) {
	plan := Plan{Node: "lab-proxmox-01"}
	expected := GuestPlan{
		VMID: 110, Name: "lab-dns-01", Hostname: "lab-dns-01", Kind: KindLXC, Owner: "boetticher/module/dns",
		Tags: []string{"boetticher", "managed", "module", "module-dns", "boetticher-module-dns", "backup"},
		Volumes: []model.PersistentVolumeDeclaration{{
			Name: "powerdns-database", Module: "dns", Guest: "lab-dns-01", Storage: "local", SizeGiB: 8,
			MountPath: "/var/lib/powerdns", Backup: true,
		}},
	}
	plan.Guests = []GuestPlan{expected}
	var err error
	volume, err := persistentVolumeParam(expected.Volumes[0])
	if err != nil {
		t.Fatal(err)
	}
	current := map[string]any{
		"name": expected.Name, "hostname": expected.Hostname, "tags": strings.Join(expected.Tags, ";"),
		"description": artifactDescription(expected.Artifact), "mp0": "local:110/vm-110-disk-1.raw," + strings.TrimPrefix(volume, "local:8") + ",size=8G",
		"mp1": "local:110/vm-110-disk-99.raw,mp=/unexpected,backup=0,size=1G",
	}
	transport := roundTripFunc(func(r *http.Request) *http.Response {
		qemuPath := "/api2/json/nodes/lab-proxmox-01/qemu/" + strconv.Itoa(expected.VMID) + "/config"
		lxcPath := "/api2/json/nodes/lab-proxmox-01/lxc/" + strconv.Itoa(expected.VMID) + "/config"
		switch {
		case r.Method == http.MethodGet && r.URL.Path == qemuPath:
			return apiResponse(http.StatusNotFound, `{"errors":{"vmid":"not found"}}`)
		case r.Method == http.MethodGet && r.URL.Path == lxcPath:
			data, marshalErr := json.Marshal(map[string]any{"data": current})
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			return response(data)
		default:
			t.Fatalf("purge inspected an undeclared volume before refusing destruction: %s %s", r.Method, r.URL.Path)
			return nil
		}
	})
	client := &Client{BaseURL: "https://pve.example/api2/json", HTTP: &http.Client{Transport: transport}}
	if err := PurgeModule(context.Background(), client, plan, "dns"); err == nil || !strings.Contains(err.Error(), "undeclared persistent volume") {
		t.Fatalf("undeclared persistent volume was not held: %v", err)
	}
}
