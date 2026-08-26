package model

import (
	"strings"
	"testing"
)

func TestRevisionIsIndependentOfModuleOrder(t *testing.T) {
	first := NewDefaultSite("installation", "age1example")
	first.TestedVersions.OPNsense = QualifiedOPNsense
	second := first
	second.Modules = append([]Module(nil), first.Modules...)
	for i, j := 0, len(second.Modules)-1; i < j; i, j = i+1, j-1 {
		second.Modules[i], second.Modules[j] = second.Modules[j], second.Modules[i]
	}
	a, err := first.Revision()
	if err != nil {
		t.Fatal(err)
	}
	b, err := second.Revision()
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("revisions differ for equivalent module sets: %s != %s", a, b)
	}
}

func TestRevisionIgnoresOperatorLocalSSHPath(t *testing.T) {
	first := NewDefaultSite("installation", "age1example")
	second := first
	first.TestedVersions.OPNsense = QualifiedOPNsense
	second.TestedVersions.OPNsense = QualifiedOPNsense
	second.SSHIdentityFile = "/different/operator/key"
	a, err := first.Revision()
	if err != nil {
		t.Fatal(err)
	}
	b, err := second.Revision()
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("operator-local SSH path changed platform revision: %s != %s", a, b)
	}
}

func TestLaterOPNsensePatchIsNotSilentlySupported(t *testing.T) {
	site := NewDefaultSite("installation", "age1example")
	site.TestedVersions.OPNsense = "26.7.1"
	if err := site.Validate(); err == nil {
		t.Fatal("later OPNsense patch was accepted without qualification")
	}
}

func TestUserManagedVMIDMustUseReservedRange(t *testing.T) {
	site := NewDefaultSite("installation", "age1example")
	site.Modules = append(site.Modules, Module{Name: "user-vm", VMID: 450, Hostname: "user-vm", Zone: "SANDBOX", Address: "10.10.50.50", Role: "user workload"})
	if err := site.Validate(); err == nil || !strings.Contains(err.Error(), "reserved user-workload range") {
		t.Fatalf("invalid user VMID was accepted: %v", err)
	}
}
