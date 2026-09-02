package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
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
	err := runKioskSetup([]string{
		"192.0.2.50",
		"--site", dir,
		"--identity-file", filepath.Join(dir, "missing-identity"),
		"--dry-run",
	}, &output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Kiosk setup: PASS dry-run only") {
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
	err := runKioskSetup([]string{
		"192.0.2.50",
		"--site", dir,
		"--identity-file", identity,
	}, &output)
	if err == nil || !strings.Contains(err.Error(), "--confirm") {
		t.Fatalf("mutation without confirmation error = %v", err)
	}
}
