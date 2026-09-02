package cli

import (
	"testing"
	"time"

	"github.com/gofastercloud/boetticher/internal/pki"
)

func TestGenerateOrReuseClientCRLReusesValidatedCache(t *testing.T) {
	now := time.Date(2026, time.August, 29, 0, 0, 0, 0, time.UTC)
	authority, err := pki.GenerateAuthority(now, "lab.home.arpa")
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := pki.IssueClient(authority, "first", "lab.home.arpa", now)
	if err != nil {
		t.Fatal(err)
	}
	revocations := []pki.Revocation{{Name: certificate.Name, Serial: certificate.Serial, RevokedAt: now.Add(-time.Minute)}}
	runtimeDir := t.TempDir()
	first, err := generateOrReuseClientCRL(authority, revocations, runtimeDir, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := generateOrReuseClientCRL(authority, revocations, runtimeDir, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("validated CRL cache was not reused")
	}
	if err := pki.ValidateCRL(authority, second, revocations, now.Add(time.Hour)); err != nil {
		t.Fatalf("reused CRL failed validation: %v", err)
	}
}

func TestGenerateOrReuseClientCRLRegeneratesForChangedRevocations(t *testing.T) {
	now := time.Date(2026, time.August, 29, 0, 0, 0, 0, time.UTC)
	authority, err := pki.GenerateAuthority(now, "lab.home.arpa")
	if err != nil {
		t.Fatal(err)
	}
	second, err := pki.IssueClient(authority, "second", "lab.home.arpa", now)
	if err != nil {
		t.Fatal(err)
	}
	runtimeDir := t.TempDir()
	firstCRL, err := generateOrReuseClientCRL(authority, nil, runtimeDir, now)
	if err != nil {
		t.Fatal(err)
	}
	revocations := []pki.Revocation{{Name: second.Name, Serial: second.Serial, RevokedAt: now}}
	secondCRL, err := generateOrReuseClientCRL(authority, revocations, runtimeDir, now)
	if err != nil {
		t.Fatal(err)
	}
	if firstCRL == secondCRL {
		t.Fatal("changed revocation set reused the old CRL")
	}
	if err := pki.ValidateCRL(authority, secondCRL, revocations, now); err != nil {
		t.Fatalf("regenerated CRL failed validation: %v", err)
	}
}
