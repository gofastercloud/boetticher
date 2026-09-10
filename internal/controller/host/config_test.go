package host

import (
	"strings"
	"testing"
)

func TestTransportForUsesInternalConnectionAndRetainsHomeFallback(t *testing.T) {
	config := LabConfig{Name: "lab", Proxmox: ProxmoxConfig{Address: HomeManagementAddress, ConnectionAddress: "10.10.99.5", User: "root", Repository: "no-subscription"}}
	transport, err := TransportFor(config)
	if err != nil {
		t.Fatal(err)
	}
	if transport.Address != "10.10.99.5" {
		t.Fatalf("active transport address = %q", transport.Address)
	}
	home, err := HomeTransportFor(config)
	if err != nil {
		t.Fatal(err)
	}
	if home.Address != HomeManagementAddress {
		t.Fatalf("HOME fallback address = %q", home.Address)
	}
	if summary := ConfigSummary(config); !strings.Contains(summary, "10.10.99.5") || !strings.Contains(summary, "HOME fallback 192.168.4.5") {
		t.Fatalf("connection summary omitted active/fallback bindings: %q", summary)
	}
}

func TestValidateConfigRejectsUnapprovedInternalConnection(t *testing.T) {
	config := LabConfig{Name: "lab", Proxmox: ProxmoxConfig{Address: HomeManagementAddress, ConnectionAddress: "10.10.99.6", User: "root", Repository: "no-subscription"}}
	if err := ValidateConfig(config); err == nil || !strings.Contains(err.Error(), "only supports Proxmox connection address") {
		t.Fatalf("unapproved connection address accepted: %v", err)
	}
}

func TestBindVerifiedEnrollmentAddressPreservesHomeAndNode(t *testing.T) {
	existing := LabConfig{Name: "lab", Proxmox: ProxmoxConfig{Address: HomeManagementAddress, User: "root", Repository: "no-subscription"}}
	updated, changed, err := bindVerifiedEnrollmentAddress(existing, "10.10.99.5", "pve")
	if err != nil || !changed {
		t.Fatalf("internal enrollment binding = %#v changed=%t err=%v", updated, changed, err)
	}
	if updated.Proxmox.Address != HomeManagementAddress || updated.Proxmox.ConnectionAddress != "10.10.99.5" || updated.Proxmox.Node != "pve" {
		t.Fatalf("enrollment binding did not preserve HOME or set active path: %#v", updated.Proxmox)
	}
	unchanged, changed, err := bindVerifiedEnrollmentAddress(updated, HomeManagementAddress, "pve")
	if err != nil || changed || unchanged.Proxmox.ConnectionAddress != "10.10.99.5" {
		t.Fatalf("HOME recovery enrollment changed active path: %#v changed=%t err=%v", unchanged.Proxmox, changed, err)
	}
}
