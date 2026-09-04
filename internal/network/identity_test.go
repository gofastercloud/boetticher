package network

import "testing"

func TestManagedModuleMACIsStableAndLocallyAdministered(t *testing.T) {
	if got, want := ManagedModuleMAC(270), "02:00:00:03:01:0e"; got != want {
		t.Fatalf("ManagedModuleMAC(270) = %q, want %q", got, want)
	}
	if ManagedModuleMAC(0) != "" || ManagedModuleMAC(0x10000) != "" {
		t.Fatal("ManagedModuleMAC accepted an invalid VMID")
	}
}
