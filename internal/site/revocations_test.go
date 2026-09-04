package site

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/gofastercloud/boetticher/internal/pki"
)

func TestLoadClientRevocationsRequiresEnforceableSerial(t *testing.T) {
	dir := t.TempDir()
	revokedDir := filepath.Join(dir, "generated", "pki", "revoked")
	if err := os.MkdirAll(revokedDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(revokedDir, "operator.yaml"), []byte("name: operator\nstatus: revoked\nrevoked_at: 2026-08-29T00:00:00Z\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadClientRevocations(dir); err == nil {
		t.Fatal("revocation without a certificate serial was accepted")
	}
}

func TestLoadClientRevocationsCanonicalizesSerials(t *testing.T) {
	dir := t.TempDir()
	revokedDir := filepath.Join(dir, "generated", "pki", "revoked")
	if err := os.MkdirAll(revokedDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(revokedDir, "operator.yaml"), []byte("name: operator\nserial: 0A\nstatus: revoked\n"), 0600); err != nil {
		t.Fatal(err)
	}
	revocations, err := LoadClientRevocations(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(revocations) != 1 || revocations[0].Serial != "a" || revocations[0].Name != "operator" {
		t.Fatalf("loaded revocations = %#v", revocations)
	}
	if _, err := pki.ParseSerial(revocations[0].Serial); err != nil {
		t.Fatal(err)
	}
}

func TestLoadClientRevocationsRejectsTooManyEntries(t *testing.T) {
	dir := t.TempDir()
	revokedDir := filepath.Join(dir, "generated", "pki", "revoked")
	if err := os.MkdirAll(revokedDir, 0700); err != nil {
		t.Fatal(err)
	}
	for index := 0; index <= maxRevocationEntries; index++ {
		path := filepath.Join(revokedDir, "client-"+fmt.Sprint(index)+".yaml")
		if err := os.WriteFile(path, []byte("name: operator\nserial: "+fmt.Sprint(index+1)+"\nstatus: revoked\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := LoadClientRevocations(dir); err == nil {
		t.Fatal("oversized revocation directory was accepted")
	}
}
