package proxmox

import (
	"encoding/json"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestNetworkInterfacePreservesHardwareEvidence(t *testing.T) {
	var iface NetworkInterface
	if err := json.Unmarshal([]byte(`{"iface":"enp5s0","type":"eth","product":"Intel X710","pci-address":"0000:05:00.0","hwaddr":"00:aa:bb:cc:dd:ee"}`), &iface); err != nil {
		t.Fatal(err)
	}
	if iface.Model != "Intel X710" || iface.PCIAddress != "0000:05:00.0" {
		t.Fatalf("hardware evidence was not preserved: %#v", iface)
	}
}

func TestAnalyzePhysicalNetworkUsesBridgeAndAddressEvidence(t *testing.T) {
	result, err := AnalyzePhysicalNetwork([]NetworkInterface{
		{Iface: "vmbr0", Type: "bridge", Address: "192.0.2.73/24", Gateway: "192.0.2.1", BridgePorts: "eno1"},
		{Iface: "vmbr1", Type: "bridge", BridgePorts: "none", BridgeVLANAware: true},
		{Iface: "eno1", Type: "eth", HWAddr: "00:11:22:33:44:55", Driver: "igc", Active: true},
		{Iface: "enp5s0", Type: "eth", HWAddr: "00:aa:bb:cc:dd:ee", Driver: "i40e", SpeedMbps: 10000, Active: false},
	}, "192.0.2.73", "")
	if err != nil || result.Mode != "physical-trunk" || result.Trunk == nil || result.Trunk.Name != "enp5s0" {
		t.Fatalf("unexpected physical discovery: %#v, %v", result, err)
	}
	if result.Upstream.Name != "eno1" || result.Upstream.PermanentMAC != "00:11:22:33:44:55" {
		t.Fatalf("unexpected upstream evidence: %#v", result.Upstream)
	}
}

func TestAnalyzePhysicalNetworkRefusesMissingDefaultRouteEvidence(t *testing.T) {
	_, err := AnalyzePhysicalNetwork([]NetworkInterface{
		{Iface: "vmbr0", Type: "bridge", Address: "192.0.2.73/24", BridgePorts: "eno1"},
		{Iface: "vmbr1", Type: "bridge", BridgePorts: "none", BridgeVLANAware: true},
		{Iface: "eno1", Type: "eth", HWAddr: "00:11:22:33:44:55", Active: true},
	}, "192.0.2.73", "")
	if err == nil || !containsText(err.Error(), "default route is not observed") {
		t.Fatalf("missing default route was not rejected: %v", err)
	}
}

func TestAnalyzePhysicalNetworkRejectsAddressedTrunkCandidate(t *testing.T) {
	result, err := AnalyzePhysicalNetwork([]NetworkInterface{
		{Iface: "vmbr0", Type: "bridge", Address: "192.0.2.73/24", Gateway: "192.0.2.1", BridgePorts: "eno1"},
		{Iface: "vmbr1", Type: "bridge", BridgePorts: "none", BridgeVLANAware: true},
		{Iface: "eno1", Type: "eth", HWAddr: "00:11:22:33:44:55", Active: true},
		{Iface: "enp5s0", Type: "eth", HWAddr: "00:aa:bb:cc:dd:ee", Address: "10.10.20.55/24", Active: false},
	}, "192.0.2.73", "")
	if err != nil || result.Mode != "virtual-only" || result.Trunk != nil {
		t.Fatalf("addressed candidate was selected: %#v, %v", result, err)
	}
}

func TestValidatePhysicalBindingAllowsDisconnectedTrunk(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	site.BootstrapAddress = "192.0.2.73"
	site.PhysicalNetwork = model.PhysicalNetwork{
		Mode:     model.ModePhysicalTrunk,
		Upstream: model.PhysicalNIC{Name: "eno1", PermanentMAC: "00:11:22:33:44:55"},
		Trunk:    model.PhysicalNIC{Name: "enp5s0", PermanentMAC: "00:aa:bb:cc:dd:ee"},
	}
	detail, err := ValidatePhysicalBinding(site, []NetworkInterface{
		{Iface: "vmbr0", Type: "bridge", Address: "192.0.2.73/24", Gateway: "192.0.2.1", BridgePorts: "eno1"},
		{Iface: "vmbr1", Type: "bridge", BridgePorts: "enp5s0", BridgeVLANAware: true},
		{Iface: "eno1", Type: "eth", HWAddr: "00:11:22:33:44:55", Active: true},
		{Iface: "enp5s0", Type: "eth", HWAddr: "00:aa:bb:cc:dd:ee", Active: false},
	})
	if err != nil || detail == "" {
		t.Fatalf("disconnected trunk was rejected: %q, %v", detail, err)
	}
}

func TestValidatePhysicalBindingDetectsStableIdentityAfterRename(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	site.BootstrapAddress = "192.0.2.73"
	site.PhysicalNetwork = model.PhysicalNetwork{
		Mode:     model.ModePhysicalTrunk,
		Upstream: model.PhysicalNIC{Name: "eno1", PermanentMAC: "00:11:22:33:44:55"},
		Trunk:    model.PhysicalNIC{Name: "enp5s0", PermanentMAC: "00:aa:bb:cc:dd:ee"},
	}
	detail, err := ValidatePhysicalBinding(site, []NetworkInterface{
		{Iface: "vmbr0", Type: "bridge", Address: "192.0.2.73/24", BridgePorts: "eno1"},
		{Iface: "vmbr1", Type: "bridge", BridgePorts: "enp7s0", BridgeVLANAware: true},
		{Iface: "eno1", Type: "eth", HWAddr: "00:11:22:33:44:55"},
		{Iface: "enp7s0", Type: "eth", HWAddr: "00:aa:bb:cc:dd:ee"},
	})
	if err != nil || detail == "" || !containsText(detail, "renamed") {
		t.Fatalf("stable rename was not reported: %q, %v", detail, err)
	}
}

func TestValidatePhysicalBindingReportsUpstreamRename(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	site.BootstrapAddress = "192.0.2.73"
	site.PhysicalNetwork = model.PhysicalNetwork{
		Mode:     model.ModeVirtualOnly,
		Upstream: model.PhysicalNIC{Name: "eno1", PermanentMAC: "00:11:22:33:44:55"},
	}
	detail, err := ValidatePhysicalBinding(site, []NetworkInterface{
		{Iface: "vmbr0", Type: "bridge", Address: "192.0.2.73/24", BridgePorts: "enp7s0"},
		{Iface: "vmbr1", Type: "bridge", BridgePorts: "none", BridgeVLANAware: true},
		{Iface: "enp7s0", Type: "eth", HWAddr: "00:11:22:33:44:55"},
	})
	if err != nil || !containsText(detail, "upstream renamed") {
		t.Fatalf("upstream rename was not reported: %q, %v", detail, err)
	}
}

func containsText(value, want string) bool {
	for i := 0; i+len(want) <= len(value); i++ {
		if value[i:i+len(want)] == want {
			return true
		}
	}
	return false
}
