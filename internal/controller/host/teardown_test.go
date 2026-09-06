package host

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTrustOnlyConfigIsValidWithoutEnrollmentBinding(t *testing.T) {
	config := LabConfig{Name: "home-lab", Proxmox: ProxmoxConfig{Address: "192.168.4.5", User: "root", Repository: "no-subscription"}}
	if err := ValidateConfig(config); err != nil {
		t.Fatal(err)
	}
	if _, err := TransportFor(config); err != nil {
		t.Fatal(err)
	}
}

func TestStorageTeardownStateRecognizesOwnedEmptyAndConflictingStates(t *testing.T) {
	disk := &Disk{BlockDevice: BlockDevice{Path: "/dev/sda"}, StableIDs: []string{"/dev/disk/by-id/ata-Timetec"}}
	exact := StoragePlan{
		Selected: disk,
		PVJSON:   json.RawMessage(`{"report":[{"pv":[{"pv_name":"/dev/sda","vg_name":"boetticher-vg"}]}]}`),
		VGJSON:   json.RawMessage(`{"report":[{"vg":[{"vg_name":"boetticher-vg"}]}]}`),
		LVJSON:   json.RawMessage(`{"report":[{"lv":[{"lv_name":"data"}]}]}`),
		Proxmox:  json.RawMessage(`{"storage":"boetticher-data","type":"lvmthin","vgname":"boetticher-vg","thinpool":"data"}`),
	}
	if state, _ := StorageTeardownState(exact); state != "owned" {
		t.Fatalf("exact state = %q", state)
	}
	empty := StoragePlan{Selected: disk}
	if state, _ := StorageTeardownState(empty); state != "absent" {
		t.Fatalf("empty state = %q", state)
	}
	guests := exact
	guests.Guests = json.RawMessage(`[{"type":"lxc","vmid":991,"name":"unexpected"}]`)
	if state, _ := StorageTeardownState(guests); state != "conflict" {
		t.Fatalf("guest state = %q", state)
	}
}

func TestTeardownCommandsAreBoundedAndDestructiveConfirmationIsExact(t *testing.T) {
	plan := NetworkPlan{State: "exact", Bridge: BridgeState{Owned: true, IPv6Disabled: true, VLANAware: true, Configured: true}}
	command, err := NetworkTeardownCommand(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"ifdown vmbr1", "ip link delete vmbr1 type bridge", "70-boetticher-vmbr1.conf", "if-up.d/boetticher-vmbr1", "auto vmbr1"} {
		if !strings.Contains(command, required) {
			t.Errorf("network teardown missing %q", required)
		}
	}
	if _, err := NetworkTeardownCommand(NetworkPlan{State: "adoptable", Bridge: plan.Bridge}); err == nil {
		t.Fatal("adoptable bridge was accepted for teardown")
	}

	storage := StoragePlan{State: "owned", Selected: &Disk{BlockDevice: BlockDevice{Path: "/dev/sda"}, StableIDs: []string{"/dev/disk/by-id/ata-Timetec"}}, Proxmox: json.RawMessage(`{"storage":"boetticher-data","type":"lvmthin","vgname":"boetticher-vg","thinpool":"data"}`), PVJSON: json.RawMessage(`{"pv_name":"/dev/sda","vg_name":"boetticher-vg"}`), VGJSON: json.RawMessage(`{"vg_name":"boetticher-vg"}`), LVJSON: json.RawMessage(`{"lv_name":"data"}`)}
	storageCommand, err := StorageTeardownCommand(storage, "/dev/disk/by-id/ata-Timetec")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(storageCommand)
	for _, required := range []string{"pvesm remove boetticher-data", "lvremove --yes boetticher-vg/data", "vgremove --yes boetticher-vg", "pvremove --yes --force --force", "wipefs --all"} {
		if !strings.Contains(storageCommand, required) {
			t.Errorf("storage teardown missing %q", required)
		}
	}
	if _, err := StorageTeardownCommand(storage, "/dev/disk/by-id/ata-other"); err == nil {
		t.Fatal("wrong storage confirmation was accepted")
	}
	if !strings.Contains(HostBaselineTeardownCommand(), "cmp -s") {
		t.Fatal("host teardown does not prove owned file contents")
	}
}

func TestBridgeIPv6TestHasExplicitCleanupAndNoFirewall(t *testing.T) {
	command, err := BridgeIPv6TestCommand()
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"pct shutdown", "pct destroy", "pct status", "pvesm list boetticher-data", "firewall=0", "tag=40", "ping -6"} {
		if !strings.Contains(command, required) {
			t.Errorf("IPv6 bridge test missing %q", required)
		}
	}
}
