package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/pki"
	"github.com/gofastercloud/boetticher/internal/site"
)

func TestKioskCertificateSelectorPinsPulseIdentity(t *testing.T) {
	selector, err := kioskCertificateSelector("https://monitor.lab.home.arpa", "lab.home.arpa")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"https://monitor.lab.home.arpa",
		"boetticher Issuing CA",
		"client-lab-display-01-kiosk.lab.home.arpa",
	} {
		if !strings.Contains(selector, want) {
			t.Errorf("certificate selector omitted %q: %s", want, selector)
		}
	}
	if !strings.HasPrefix(selector, "'") || !strings.HasSuffix(selector, "'") {
		t.Fatalf("certificate selector is not shell-safe: %s", selector)
	}
}

func TestCompanionProvisioningUsesEmbeddedSources(t *testing.T) {
	root, cleanup, err := kioskSourceRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	repositoryRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if root == repositoryRoot || strings.HasPrefix(root, repositoryRoot+string(filepath.Separator)) {
		t.Fatalf("companion provisioning source came from the filesystem checkout: %s", root)
	}
	for _, relative := range []string{"ansible/companion.yml", "pi/kiosk/libexec/boetticher-blinkt"} {
		if _, err := os.Stat(filepath.Join(root, relative)); err != nil {
			t.Fatalf("embedded companion source is incomplete: %v", err)
		}
	}
}

func TestKioskCertificatePolicyUsesStringifiedChromeEntries(t *testing.T) {
	policy, err := kioskCertificatePolicy("https://monitor.lab.home.arpa", "lab.home.arpa")
	if err != nil {
		t.Fatal(err)
	}
	var outer struct {
		Entries []string `json:"AutoSelectCertificateForUrls"`
	}
	if err := json.Unmarshal([]byte(`{"AutoSelectCertificateForUrls":`+policy+`}`), &outer); err != nil {
		t.Fatalf("policy is not valid JSON: %v", err)
	}
	if len(outer.Entries) != 1 {
		t.Fatalf("policy entries = %d, want 1", len(outer.Entries))
	}
	var entry map[string]any
	if err := json.Unmarshal([]byte(outer.Entries[0]), &entry); err != nil {
		t.Fatalf("policy entry is not stringified JSON: %v", err)
	}
	if entry["pattern"] != "https://monitor.lab.home.arpa" {
		t.Fatalf("policy pattern = %v", entry["pattern"])
	}
}

func TestNormalizeCompanionMigrationArgsAcceptsAddressBeforeOptions(t *testing.T) {
	got, err := normalizeCompanionMigrationArgs([]string{"192.0.2.50", "--site", "./site", "--proxmox-ca", "./ca.pem"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--site", "./site", "--proxmox-ca", "./ca.pem", "192.0.2.50"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("normalized args = %#v, want %#v", got, want)
	}
}

func TestKioskSetupDryRunDoesNotTouchPKIOrPi(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BOETTICHER_RUNTIME_DIR", filepath.Join(t.TempDir(), "runtime"))
	config := model.ConfigFromSite(model.NewDefaultSite("installation", "age1example"))
	config.BootstrapAddress = "192.0.2.10"
	enabled := true
	config.Companion = &model.CompanionConfig{
		Enabled: &enabled, EthernetMAC: "dc:a6:32:e9:dd:82",
		Display: &model.CompanionCapabilityConfig{Enabled: &enabled}, StreamDeck: &model.CompanionCapabilityConfig{Enabled: &enabled}, PulseAgent: &model.CompanionCapabilityConfig{Enabled: &enabled},
	}
	if err := site.SaveConfig(dir, config); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	err := runCompanionSetup([]string{
		"--site", dir,
		"--identity-file", filepath.Join(dir, "missing-identity"),
		"--dry-run",
	}, &output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Companion setup: PASS dry-run only") {
		t.Fatalf("unexpected dry-run output: %s", output.String())
	}
	if !strings.Contains(output.String(), "Companion target: pi@"+model.CompanionAddress+":22") {
		t.Fatalf("setup did not derive the SERVERS address: %s", output.String())
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("BOETTICHER_RUNTIME_DIR"), "installation", "pki", kioskClientName)); !os.IsNotExist(err) {
		t.Fatalf("dry-run created kiosk PKI runtime: %v", err)
	}
}

func TestKioskSetupRequiresConfirmationForMutation(t *testing.T) {
	dir := t.TempDir()
	config := model.ConfigFromSite(model.NewDefaultSite("installation", "age1example"))
	config.BootstrapAddress = "192.0.2.10"
	enabled := true
	config.Companion = &model.CompanionConfig{Enabled: &enabled, EthernetMAC: "dc:a6:32:e9:dd:82"}
	if err := site.SaveConfig(dir, config); err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(identity, []byte("not-a-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err := runCompanionSetup([]string{
		"--site", dir,
		"--identity-file", identity,
	}, &output)
	if err == nil || !strings.Contains(err.Error(), "--confirm") {
		t.Fatalf("mutation without confirmation error = %v", err)
	}
}

func TestCompanionAddRecordsTypedIdentityAndDerivedReservationOnly(t *testing.T) {
	dir := t.TempDir()
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	if err := site.SaveConfig(dir, config); err != nil {
		t.Fatal(err)
	}

	var preview bytes.Buffer
	if err := runCompanionAdd([]string{"--site", dir, "--mac", "DC:A6:32:E9:DD:82", "--dry-run"}, &preview); err != nil {
		t.Fatal(err)
	}
	unchanged, err := site.LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Companion != nil {
		t.Fatalf("dry-run changed desired state: %#v", unchanged.Companion)
	}
	if !strings.Contains(preview.String(), model.CompanionHostname) || !strings.Contains(preview.String(), model.CompanionAddress) || !strings.Contains(preview.String(), "desired state only") {
		t.Fatalf("companion preview omitted its derived plan: %s", preview.String())
	}

	var output bytes.Buffer
	if err := runCompanionAdd([]string{"--site", dir, "--mac", "DC:A6:32:E9:DD:82", "--confirm"}, &output); err != nil {
		t.Fatal(err)
	}
	saved, err := site.LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Companion == nil || saved.Companion.EthernetMAC != "dc:a6:32:e9:dd:82" || !saved.Companion.Capabilities().Enabled {
		t.Fatalf("typed companion identity was not saved: %#v", saved.Companion)
	}
	if len(saved.DHCPReservations) != 0 {
		t.Fatalf("derived reservation was duplicated in site.yml: %#v", saved.DHCPReservations)
	}
	resolved, err := site.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved.DHCPReservations) != 1 || resolved.DHCPReservations[0].Address != model.CompanionAddress || resolved.DHCPReservations[0].MAC != "dc:a6:32:e9:dd:82" {
		t.Fatalf("derived reservation is missing: %#v", resolved.DHCPReservations)
	}
}

func TestCompanionSetupRequiresCompanionAdd(t *testing.T) {
	dir := t.TempDir()
	if err := site.SaveConfig(dir, model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))); err != nil {
		t.Fatal(err)
	}
	err := runCompanionSetup([]string{"--site", dir, "--dry-run"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "companion add --mac") {
		t.Fatalf("setup accepted an unconfigured companion: %v", err)
	}
}

func TestCompanionSetupRejectsAnArbitraryAddress(t *testing.T) {
	dir := t.TempDir()
	enabled := true
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	config.Companion = &model.CompanionConfig{Enabled: &enabled, EthernetMAC: "dc:a6:32:e9:dd:82"}
	if err := site.SaveConfig(dir, config); err != nil {
		t.Fatal(err)
	}
	err := runCompanionSetup([]string{"192.168.4.6", "--site", dir, "--dry-run"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "does not accept an address") {
		t.Fatalf("setup accepted an arbitrary address: %v", err)
	}
}

func TestCompanionStatusRunnerPinsTheLogicalHostIdentity(t *testing.T) {
	runner := companionStatusSSHRunner("/tmp/companion-ssh.conf")
	if runner.ConfigFile != "/tmp/companion-ssh.conf" || runner.HostAlias != "boetticher-companion" || runner.HostKeyAlias != model.CompanionHostname {
		t.Fatalf("unexpected Companion status runner: %#v", runner)
	}
}

func TestCompanionAddAdoptsOnlyAnExactGenericReservation(t *testing.T) {
	dir := t.TempDir()
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	config.DHCPReservations = []model.DHCPReservation{{
		Zone: model.CompanionZone, Hostname: model.CompanionHostname, Address: model.CompanionAddress, MAC: "dc:a6:32:e9:dd:82",
	}}
	if err := site.SaveConfig(dir, config); err != nil {
		t.Fatal(err)
	}
	if err := runCompanionAdd([]string{"--site", dir, "--mac", "dc:a6:32:e9:dd:82", "--confirm"}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	saved, err := site.LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.DHCPReservations) != 0 {
		t.Fatalf("exact generic reservation was not adopted: %#v", saved.DHCPReservations)
	}

	conflictDir := t.TempDir()
	config.Companion = nil
	config.DHCPReservations[0].MAC = "dc:a6:32:e9:dd:83"
	if err := site.SaveConfig(conflictDir, config); err != nil {
		t.Fatal(err)
	}
	err = runCompanionAdd([]string{"--site", conflictDir, "--mac", "dc:a6:32:e9:dd:82", "--confirm"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("conflicting reservation was adopted: %v", err)
	}
}

func TestDisabledCompanionCertificateTeardownRecordsRevocationAndRemovesCache(t *testing.T) {
	dir := t.TempDir()
	runtime := filepath.Join(t.TempDir(), "runtime")
	t.Setenv("BOETTICHER_RUNTIME_DIR", runtime)
	s := model.NewDefaultSite("installation", "age1example")
	authority, err := pki.GenerateAuthority(time.Now().UTC(), s.Network.Domain)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := pki.IssueClient(authority, kioskClientName, s.Network.Domain, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	runtimeDir := filepath.Join(site.RuntimeDir(s), "pki", kioskClientName)
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, file := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{filepath.Join(runtimeDir, "client.key.pem"), []byte(issued.KeyPEM), 0600},
		{filepath.Join(runtimeDir, "client.crt.pem"), []byte(issued.CertPEM), 0644},
		{filepath.Join(runtimeDir, "chain.crt.pem"), []byte(issued.ChainPEM), 0644},
	} {
		if err := os.WriteFile(file.path, file.data, file.mode); err != nil {
			t.Fatal(err)
		}
	}
	metadataPath := filepath.Join(dir, "generated", "pki", kioskClientName+".yaml")
	if err := os.MkdirAll(filepath.Dir(metadataPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metadataPath, []byte("name: "+kioskClientName+"\nserial: "+issued.Serial+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "generated", "pki", "revoked"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := revokeAndRemoveCompanionCertificate(dir, s, kioskClientName, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(runtimeDir); !os.IsNotExist(err) {
		t.Fatalf("cached companion certificate directory remains: %v", err)
	}
	if _, err := os.Stat(metadataPath); !os.IsNotExist(err) {
		t.Fatalf("cached companion certificate metadata remains: %v", err)
	}
	revocations, err := site.LoadClientRevocations(dir)
	if err != nil || len(revocations) != 1 || revocations[0].Serial != issued.Serial {
		t.Fatalf("companion revocations = %#v, %v", revocations, err)
	}
}

func TestValidateKioskSSHInputsRejectsSymlinkedKnownHostsParent(t *testing.T) {
	dir := t.TempDir()
	identity := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(identity, []byte("not-a-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	external := t.TempDir()
	if err := os.Symlink(external, filepath.Join(dir, "generated")); err != nil {
		t.Fatal(err)
	}
	err := validateKioskSSHInputs(identity, filepath.Join(dir, "generated", "ssh", "companion_known_hosts"), false)
	if err == nil {
		t.Fatal("symlinked kiosk known-hosts parent was accepted")
	}
}

func TestEnsureKioskClientCertificateReplacesMismatchedCachedLeaf(t *testing.T) {
	now := time.Now().UTC()
	authority, err := pki.GenerateAuthority(now, "lab.home.arpa")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := pki.IssueClient(authority, kioskClientName, "lab.home.arpa", now)
	if err != nil {
		t.Fatal(err)
	}
	other, err := pki.IssueClient(authority, "different-client", "lab.home.arpa", now)
	if err != nil {
		t.Fatal(err)
	}

	runtime := filepath.Join(t.TempDir(), "runtime")
	t.Setenv("BOETTICHER_RUNTIME_DIR", runtime)
	s := model.NewDefaultSite("installation", "age1example")
	runtimeDir := filepath.Join(site.RuntimeDir(s), "pki", kioskClientName)
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runtimeDir, "client.key.pem"), []byte(issued.KeyPEM), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runtimeDir, "client.crt.pem"), []byte(other.CertPEM), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runtimeDir, "chain.crt.pem"), []byte(issued.ChainPEM), 0644); err != nil {
		t.Fatal(err)
	}

	got, err := ensureKioskClientCertificate(t.TempDir(), s, authority)
	if err != nil {
		t.Fatal(err)
	}
	if got.CertPEM == issued.CertPEM || got.CertPEM == other.CertPEM {
		t.Fatal("mismatched cached kiosk certificate was reused")
	}
}

func TestEnsureKioskClientCertificateRetainsValidatedCachedIdentityMaterial(t *testing.T) {
	now := time.Now().UTC()
	authority, err := pki.GenerateAuthority(now, "lab.home.arpa")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := pki.IssueClient(authority, kioskClientName, "lab.home.arpa", now)
	if err != nil {
		t.Fatal(err)
	}

	runtime := filepath.Join(t.TempDir(), "runtime")
	t.Setenv("BOETTICHER_RUNTIME_DIR", runtime)
	s := model.NewDefaultSite("installation", "age1example")
	runtimeDir := filepath.Join(site.RuntimeDir(s), "pki", kioskClientName)
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	for path, contents := range map[string]string{
		"client.key.pem": issued.KeyPEM,
		"client.crt.pem": issued.CertPEM,
		"chain.crt.pem":  issued.ChainPEM,
	} {
		if err := os.WriteFile(filepath.Join(runtimeDir, path), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}

	got, err := ensureKioskClientCertificate(t.TempDir(), s, authority)
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyPEM != issued.KeyPEM || got.CertPEM != issued.CertPEM || got.ChainPEM != issued.ChainPEM {
		t.Fatal("validated cached kiosk identity material was not preserved")
	}
}

func TestEnsureKioskClientCertificateRepairsPartialCachedIdentity(t *testing.T) {
	now := time.Now().UTC()
	authority, err := pki.GenerateAuthority(now, "lab.home.arpa")
	if err != nil {
		t.Fatal(err)
	}

	runtime := filepath.Join(t.TempDir(), "runtime")
	t.Setenv("BOETTICHER_RUNTIME_DIR", runtime)
	s := model.NewDefaultSite("installation", "age1example")
	runtimeDir := filepath.Join(site.RuntimeDir(s), "pki", kioskClientName)
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runtimeDir, "client.key.pem"), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := ensureKioskClientCertificate(t.TempDir(), s, authority)
	if err != nil {
		t.Fatalf("partial kiosk identity was not repaired: %v", err)
	}
	for name, want := range map[string]string{
		"client.key.pem": got.KeyPEM,
		"client.crt.pem": got.CertPEM,
		"chain.crt.pem":  got.ChainPEM,
	} {
		data, err := os.ReadFile(filepath.Join(runtimeDir, name))
		if err != nil || string(data) != want {
			t.Fatalf("repaired kiosk identity %s = %q, %v", name, data, err)
		}
	}
}
