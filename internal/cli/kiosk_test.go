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
	for _, relative := range []string{"ansible/companion.yml", "pi/kiosk/visualizer/index.html"} {
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

func TestNormalizeKioskArgsAcceptsAddressBeforeOptions(t *testing.T) {
	got, err := normalizeKioskArgs([]string{"192.0.2.50", "--site", "./site", "--port", "2222"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--site", "./site", "--port", "2222", "192.0.2.50"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("normalized args = %#v, want %#v", got, want)
	}
}

func TestKioskSetupDryRunDoesNotTouchPKIOrPi(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BOETTICHER_RUNTIME_DIR", filepath.Join(t.TempDir(), "runtime"))
	config := model.ConfigFromSite(model.NewDefaultSite("installation", "age1example"))
	if err := site.SaveConfig(dir, config); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	err := runCompanionSetup([]string{
		"192.0.2.50",
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
	if _, err := os.Stat(filepath.Join(os.Getenv("BOETTICHER_RUNTIME_DIR"), "installation", "pki", kioskClientName)); !os.IsNotExist(err) {
		t.Fatalf("dry-run created kiosk PKI runtime: %v", err)
	}
}

func TestKioskSetupRequiresConfirmationForMutation(t *testing.T) {
	dir := t.TempDir()
	config := model.ConfigFromSite(model.NewDefaultSite("installation", "age1example"))
	if err := site.SaveConfig(dir, config); err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(identity, []byte("not-a-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err := runCompanionSetup([]string{
		"192.0.2.50",
		"--site", dir,
		"--identity-file", identity,
	}, &output)
	if err == nil || !strings.Contains(err.Error(), "--confirm") {
		t.Fatalf("mutation without confirmation error = %v", err)
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
