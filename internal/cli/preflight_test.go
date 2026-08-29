package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLooksLikeProxmoxControllerRequiresIndependentMarkers(t *testing.T) {
	root := t.TempDir()
	if looksLikeProxmoxControllerAt(root, "/usr/sbin/pveversion") {
		t.Fatal("empty Linux controller was classified as Proxmox")
	}
	if err := os.MkdirAll(filepath.Join(root, "etc", "pve"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "var", "lib", "pve-cluster"), 0o755); err != nil {
		t.Fatal(err)
	}
	if looksLikeProxmoxControllerAt(root, "/usr/sbin/pveversion") {
		t.Fatal("filesystem markers without pveversion were classified as Proxmox")
	}
	if err := os.MkdirAll(filepath.Join(root, "usr", "sbin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr", "sbin", "pveversion"), []byte("test"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !looksLikeProxmoxControllerAt(root, "/usr/sbin/pveversion") {
		t.Fatal("complete Proxmox marker set was not classified")
	}
}

func TestOrdinaryLinuxControllerMarkersRemainUnclassified(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc", "pve"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "var", "lib", "pve-cluster"), 0o755); err != nil {
		t.Fatal(err)
	}
	if looksLikeProxmoxControllerAt(root, "/usr/sbin/pveversion") {
		t.Fatal("ordinary Linux test root was classified as Proxmox")
	}
}

func TestSSHKeyscanUsesTheOpenSSHVersionProbe(t *testing.T) {
}
