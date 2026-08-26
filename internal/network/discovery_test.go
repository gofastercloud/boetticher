package network

import "testing"

func baseEvidence() Evidence {
	return Evidence{
		DefaultRouteInterface: "eno1",
		BootstrapInterface:    "eno1",
		BootstrapAddress:      "192.0.2.73",
		VMbr0Members:          []string{"eno1"},
		Interfaces: []Interface{
			{Name: "eno1", PermanentMAC: "00:11:22:33:44:55", PhysicalEthernet: true, Addresses: []string{"192.0.2.73/24"}, DefaultRoute: true, Carrier: true},
		},
	}
}

func TestSingleNICIsVirtualOnly(t *testing.T) {
	result, err := Analyze(baseEvidence(), "")
	if err != nil {
		t.Fatal(err)
	}
	if result.Mode != ModeVirtualOnly || result.Trunk != nil || result.Upstream.Name != "eno1" {
		t.Fatalf("unexpected single-NIC result: %#v", result)
	}
}

func TestTwoNICsSelectOnlyUnusedCandidate(t *testing.T) {
	evidence := baseEvidence()
	evidence.Interfaces = append(evidence.Interfaces, Interface{Name: "enp5s0", PermanentMAC: "00:aa:bb:cc:dd:ee", PhysicalEthernet: true, Carrier: false})
	result, err := Analyze(evidence, "")
	if err != nil || result.Mode != ModePhysicalTrunk || result.Trunk == nil || result.Trunk.Name != "enp5s0" {
		t.Fatalf("unexpected two-NIC result: %#v, %v", result, err)
	}
}

func TestMultipleCandidatesRequireExplicitSelection(t *testing.T) {
	evidence := baseEvidence()
	evidence.Interfaces = append(evidence.Interfaces,
		Interface{Name: "enp5s0", PermanentMAC: "00:aa:bb:cc:dd:ee", PhysicalEthernet: true, Carrier: true},
		Interface{Name: "enp6s0", PermanentMAC: "00:aa:bb:cc:dd:ff", PhysicalEthernet: true, Carrier: false},
	)
	result, err := Analyze(evidence, "")
	if err != nil || result.Mode != ModeSelectionNeeded || len(result.Candidates) != 2 {
		t.Fatalf("unexpected ambiguous result: %#v, %v", result, err)
	}
	selected, err := Analyze(evidence, "enp6s0")
	if err != nil || selected.Mode != ModePhysicalTrunk || selected.Trunk == nil || selected.Trunk.Name != "enp6s0" {
		t.Fatalf("explicit selection failed: %#v, %v", selected, err)
	}
}

func TestUnsafeCandidatesAreRejectedAndDisconnectedIsAllowed(t *testing.T) {
	evidence := baseEvidence()
	evidence.Interfaces = append(evidence.Interfaces,
		Interface{Name: "enp5s0", PermanentMAC: "00:aa:bb:cc:dd:ee", PhysicalEthernet: true, Addresses: []string{"10.0.0.2/24"}},
		Interface{Name: "enp6s0", PermanentMAC: "00:aa:bb:cc:dd:ff", PhysicalEthernet: true, Bridge: "vmbr9"},
		Interface{Name: "enp7s0", PermanentMAC: "00:aa:bb:cc:dd:00", PhysicalEthernet: true, IPv6Addresses: []string{"2001:db8::7/64"}},
		Interface{Name: "enp8s0", PermanentMAC: "00:aa:bb:cc:dd:11", PhysicalEthernet: true, Carrier: false},
	)
	result, err := Analyze(evidence, "")
	if err != nil || result.Mode != ModePhysicalTrunk || result.Trunk == nil || result.Trunk.Name != "enp8s0" {
		t.Fatalf("unsafe candidate handling failed: %#v, %v", result, err)
	}
}

func TestAmbiguousUpstreamStopsBeforeMutation(t *testing.T) {
	evidence := baseEvidence()
	evidence.DefaultRouteInterface = "enp5s0"
	if _, err := Analyze(evidence, ""); err == nil || err.Error() != "HOLD: upstream interface identity is ambiguous" {
		t.Fatalf("unexpected upstream ambiguity result: %v", err)
	}
}

func TestStableIdentitySurvivesInterfaceRename(t *testing.T) {
	evidence := baseEvidence()
	evidence.Interfaces[0].Name = "enp7s0"
	evidence.BootstrapInterface = "enp7s0"
	evidence.DefaultRouteInterface = "enp7s0"
	evidence.VMbr0Members = []string{"enp7s0"}
	evidence.Interfaces = append(evidence.Interfaces, Interface{Name: "eno1", PermanentMAC: "00:aa:bb:cc:dd:ee", PhysicalEthernet: true})
	result, err := Analyze(evidence, "")
	if err != nil || result.Upstream.PermanentMAC != "00:11:22:33:44:55" {
		t.Fatalf("stable identity was not preserved: %#v, %v", result, err)
	}
}

func TestConfiguredTrunkStillPassesSafetyChecks(t *testing.T) {
	evidence := baseEvidence()
	evidence.ConfiguredTrunk = "enp5s0"
	evidence.Interfaces = append(evidence.Interfaces, Interface{
		Name: "enp5s0", PermanentMAC: "00:aa:bb:cc:dd:ee", PhysicalEthernet: true, Bridge: "vmbr1",
	})
	result, err := Analyze(evidence, "")
	if err != nil || result.Mode != ModePhysicalTrunk || result.Trunk == nil || result.Trunk.Name != "enp5s0" {
		t.Fatalf("configured trunk was not recognized: %#v, %v", result, err)
	}
	evidence.Interfaces[1].Addresses = []string{"10.10.20.55/24"}
	result, err = Analyze(evidence, "")
	if err != nil || result.Mode != ModeVirtualOnly || result.Trunk != nil {
		t.Fatalf("unsafe configured trunk was adopted: %#v, %v", result, err)
	}
}
