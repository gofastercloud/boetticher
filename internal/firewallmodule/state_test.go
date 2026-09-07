package firewallmodule

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureCredentialPersistsAndReusesWithoutOutputValue(t *testing.T) {
	dir := t.TempDir()
	credential, created, err := EnsureCredential(filepath.Join(dir, "firewall"))
	if err != nil || !created || credential == "" {
		t.Fatalf("first credential = %q created=%t err=%v", credential, created, err)
	}
	reused, created, err := EnsureCredential(filepath.Join(dir, "firewall"))
	if err != nil || created || reused != credential {
		t.Fatalf("reused credential = %q created=%t err=%v", reused, created, err)
	}
	info, err := os.Stat(filepath.Join(dir, "firewall", credentialFile))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("credential mode = %v err=%v", info.Mode().Perm(), err)
	}
}

func TestTrustRoundTripAndTeardown(t *testing.T) {
	dir := t.TempDir()
	pem := []byte("-----BEGIN CERTIFICATE-----\nexample\n-----END CERTIFICATE-----\n")
	if err := StoreTrust(filepath.Join(dir, "firewall"), pem); err != nil {
		t.Fatal(err)
	}
	read, err := LoadTrust(filepath.Join(dir, "firewall"))
	if err != nil || string(read) != string(pem) {
		t.Fatalf("trust read = %q err=%v", read, err)
	}
	if err := RemoveState(filepath.Join(dir, "firewall")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "firewall")); !os.IsNotExist(err) {
		t.Fatalf("provider state remains after teardown: %v", err)
	}
	if strings.Contains(string(read), "credential") {
		t.Fatal("trust fixture unexpectedly contains credential material")
	}
}
