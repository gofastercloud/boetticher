package cli

import (
	"bytes"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofastercloud/boetticher/internal/pki"
)

func TestRevokeClientUsesDurableMetadataWhenRuntimeCertificateIsMissing(t *testing.T) {
	siteDir := t.TempDir()
	metadataDir := filepath.Join(siteDir, "generated", "pki")
	if err := os.MkdirAll(metadataDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(metadataDir, "operator.yaml"), []byte("name: operator\nserial: 0A\ncreated_at: 2026-08-29T00:00:00Z\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	runtimeDir := filepath.Join(siteDir, "generated", "runtime", "pki", "operator")
	if err := revokeClient(siteDir, runtimeDir, "operator", &output); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(siteDir, "generated", "pki", "revoked", "operator.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "serial: a") {
		t.Fatalf("revocation record did not use durable certificate serial: %s", data)
	}
}

func TestPKIRejectsUnsafeClientNameBeforeLoadingSite(t *testing.T) {
	for _, name := range []string{"../outside", "/absolute", "with/slash"} {
		if err := runPKI([]string{"client", "export", name, "--site", filepath.Join(t.TempDir(), "missing")}, &bytes.Buffer{}); err == nil {
			t.Fatalf("unsafe client name %q was accepted", name)
		}
	}
}

func TestAppleTrustProfileIsDeterministicAndContainsNoPrivateMaterial(t *testing.T) {
	authority, err := pki.GenerateAuthority(time.Unix(0, 0), "lab.home.arpa")
	if err != nil {
		t.Fatal(err)
	}
	first, err := appleTrustProfile(authority.RootCertPEM)
	if err != nil {
		t.Fatal(err)
	}
	second, err := appleTrustProfile(authority.RootCertPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("Apple trust profile is not deterministic")
	}
	var document struct {
		XMLName xml.Name `xml:"plist"`
	}
	if err := xml.Unmarshal(first, &document); err != nil {
		t.Fatalf("Apple trust profile is not valid XML: %v", err)
	}
	text := string(first)
	for _, required := range []string{"com.apple.security.root", "PayloadContent", "boetticher-root-ca.cer"} {
		if !strings.Contains(text, required) {
			t.Fatalf("Apple trust profile omitted %q", required)
		}
	}
	if strings.Contains(text, "PRIVATE KEY") {
		t.Fatal("Apple trust profile contains private key material")
	}
}
