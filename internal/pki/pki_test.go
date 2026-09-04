package pki

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestAuthorityAndClientCertificate(t *testing.T) {
	authority, err := GenerateAuthority(time.Unix(0, 0), "lab.home.arpa")
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := PublicMetadata(authority)
	if err != nil || metadata["root_ca_cn"] != "boetticher Root CA" {
		t.Fatalf("unexpected CA metadata: %#v, %v", metadata, err)
	}
	client, err := IssueClient(authority, "laptop", "lab.home.arpa", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(client.CertPEM))
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(certificate.ExtKeyUsage) != 1 || certificate.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("client certificate does not have client auth usage: %v", certificate.ExtKeyUsage)
	}
}

func TestClientNameCannotEscapeRuntimeDirectory(t *testing.T) {
	if err := ValidateClientName("../outside"); err == nil {
		t.Fatal("path traversal client name was accepted")
	}
}

func TestGenerateCRLRevokesExactCertificateSerial(t *testing.T) {
	authority, err := GenerateAuthority(time.Unix(0, 0), "lab.home.arpa")
	if err != nil {
		t.Fatal(err)
	}
	first, err := IssueClient(authority, "first", "lab.home.arpa", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	second, err := IssueClient(authority, "second", "lab.home.arpa", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(120, 0)
	crlPEM, err := GenerateCRL(authority, []Revocation{{Name: first.Name, Serial: first.Serial, RevokedAt: time.Unix(60, 0)}}, now)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode([]byte(crlPEM))
	if block == nil || block.Type != "X509 CRL" {
		t.Fatalf("CRL PEM block = %#v", block)
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := parseCert(authority.IssuingCertPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		t.Fatalf("CRL signature did not verify: %v", err)
	}
	if !crl.NextUpdate.After(now.AddDate(9, 0, 0)) {
		t.Fatalf("CRL validity is too short: next update %s", crl.NextUpdate)
	}
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Text(16) != first.Serial {
		t.Fatalf("unexpected revoked entries: %#v", crl.RevokedCertificateEntries)
	}
	if crl.RevokedCertificateEntries[0].SerialNumber.Text(16) == second.Serial {
		t.Fatal("CRL revoked an unrelated certificate")
	}
	if len(rest) != 0 {
		t.Fatalf("CRL contains unexpected trailing material: %q", rest)
	}
}

func TestValidateCRLRequiresCurrentAuthorityAndExactRevocations(t *testing.T) {
	now := time.Date(2026, time.August, 29, 0, 0, 0, 0, time.UTC)
	authority, err := GenerateAuthority(now, "lab.home.arpa")
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := IssueClient(authority, "first", "lab.home.arpa", now)
	if err != nil {
		t.Fatal(err)
	}
	revocations := []Revocation{{Name: certificate.Name, Serial: certificate.Serial, RevokedAt: now.Add(-time.Minute)}}
	crl, err := GenerateCRL(authority, revocations, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCRL(authority, crl, revocations, now.Add(time.Minute)); err != nil {
		t.Fatalf("valid CRL rejected: %v", err)
	}
	if err := ValidateCRL(authority, crl, nil, now.Add(time.Minute)); err == nil {
		t.Fatal("CRL with an unexpected revocation set was accepted")
	}
	if err := ValidateCRL(authority, crl+"tampered", revocations, now.Add(time.Minute)); err == nil {
		t.Fatal("tampered CRL was accepted")
	}
}

func TestValidateCRLDoesNotRequireTheColdRootKey(t *testing.T) {
	now := time.Date(2026, time.August, 29, 0, 0, 0, 0, time.UTC)
	authority, err := GenerateAuthority(now, "lab.home.arpa")
	if err != nil {
		t.Fatal(err)
	}
	crl, err := GenerateCRL(authority, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	authority.RootKeyPEM = ""
	if err := ValidateCRL(authority, crl, nil, now.Add(time.Minute)); err != nil {
		t.Fatalf("CRL validation required the cold root key: %v", err)
	}
}

func TestGenerateRootCRLIsSignedByRoot(t *testing.T) {
	now := time.Date(2026, time.August, 29, 0, 0, 0, 0, time.UTC)
	authority, err := GenerateAuthority(now, "lab.home.arpa")
	if err != nil {
		t.Fatal(err)
	}
	crl, err := GenerateRootCRL(authority, now)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(crl))
	if block == nil || block.Type != "X509 CRL" {
		t.Fatalf("root CRL PEM block = %#v", block)
	}
	parsed, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	root, err := parseCert(authority.RootCertPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.CheckSignatureFrom(root); err != nil {
		t.Fatalf("root CRL signature invalid: %v", err)
	}
	if len(parsed.RevokedCertificateEntries) != 0 {
		t.Fatal("root CRL unexpectedly contains revoked entries")
	}
}
