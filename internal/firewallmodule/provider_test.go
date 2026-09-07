package firewallmodule

import (
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/proxmox"
)

func TestProviderVMParamsUseCapabilityIdentityAndTwoNICs(t *testing.T) {
	params := providerVMParams()
	if params.Get("name") != ProviderName || params.Get("net0") != ProviderNIC0 || params.Get("net1") != ProviderNIC1 || params.Get("net2") != "" {
		t.Fatalf("provider params = %v", params)
	}
	if !strings.Contains(params.Get("tags"), providerOwnerTag) || strings.Contains(params.Get("tags"), "openwrt") {
		t.Fatalf("provider tags leak or omit ownership: %q", params.Get("tags"))
	}
}

func TestValidateProviderVMRejectsConflictsAndForeignNICs(t *testing.T) {
	base := map[string]any{"name": ProviderName, "tags": "boetticher;managed;module;" + providerOwnerTag, "net0": ProviderNIC0, "net1": ProviderNIC1, "scsi0": "boetticher-data:vm-280-disk-0"}
	if err := validateProviderVM(base, "boetticher-data"); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(map[string]any){
		func(current map[string]any) { current["name"] = "lab-openwrt-01" },
		func(current map[string]any) { current["net2"] = "virtio,bridge=vmbr1,firewall=1" },
		func(current map[string]any) { current["scsi0"] = "local:foreign" },
	} {
		current := cloneMap(base)
		edit(current)
		if err := validateProviderVM(current, "boetticher-data"); err == nil || !strings.Contains(err.Error(), "HOLD") {
			t.Fatalf("provider conflict was accepted: %v", err)
		}
	}
}

func TestValidateVLANBridgeRequiresHostOwnedShape(t *testing.T) {
	interfaces := []proxmox.NetworkInterface{{Iface: "vmbr0", Type: "bridge"}, {Iface: "vmbr1", Type: "bridge", BridgeVLANAware: true, BridgePorts: "none"}}
	if err := ValidateVLANBridge(interfaces); err != nil {
		t.Fatal(err)
	}
	interfaces[1].BridgeVLANAware = false
	if err := ValidateVLANBridge(interfaces); err == nil || !strings.Contains(err.Error(), "vmbr1") {
		t.Fatalf("incompatible vmbr1 accepted: %v", err)
	}
}

func cloneMap(input map[string]any) map[string]any {
	output := make(map[string]any, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}
