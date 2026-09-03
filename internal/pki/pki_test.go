package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
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

func TestSignServerCSRAcceptsOnlyApprovedSANs(t *testing.T) {
	authority, err := GenerateAuthority(time.Unix(0, 0), "lab.home.arpa")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "monitor.lab.home.arpa"},
		DNSNames: []string{"monitor.lab.home.arpa", "lab-monitor-01.lab.home.arpa"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := SignServerCSR(authority, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: request})), "monitor", "lab.home.arpa", []string{"lab-monitor-01.lab.home.arpa"}, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if certificate.CertPEM == "" {
		t.Fatal("signed endpoint certificate missing")
	}
	_, err = SignServerCSR(authority, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: request})), "rogue", "lab.home.arpa", []string{"lab-rogue-01.lab.home.arpa"}, time.Unix(0, 0))
	if err == nil {
		t.Fatal("controller signed a CSR for an unapproved identity")
	}
}

func TestSignClientCSRKeepsEndpointKeyOutsideControllerCertificate(t *testing.T) {
	authority, err := GenerateAuthority(time.Unix(0, 0), "lab.home.arpa")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "client-lab-proxmox-01.lab.home.arpa"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := SignClientCSR(authority, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: request})), "lab-proxmox-01", "lab.home.arpa", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if certificate.CertPEM == "" || certificate.KeyPEM != "" {
		t.Fatalf("client CSR signer returned unexpected key material: %#v", certificate)
	}
	block, _ := pem.Decode([]byte(certificate.CertPEM))
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.ExtKeyUsage) != 1 || parsed.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("client CSR certificate has wrong usage: %v", parsed.ExtKeyUsage)
	}
}

func TestSignServiceClientCSRRequiresExactIdentityWithoutSANs(t *testing.T) {
	authority, err := GenerateAuthority(time.Unix(0, 0), "lab.home.arpa")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	makeRequest := func(commonName string, dnsNames []string) string {
		request, requestErr := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}, DNSNames: dnsNames}, key)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: request}))
	}
	certificate, err := SignServiceClientCSR(authority, makeRequest("aiops-pulse-read", nil), "aiops-pulse-read", time.Unix(0, 0))
	if err != nil || certificate.CertPEM == "" || certificate.KeyPEM != "" {
		t.Fatalf("service client certificate = %#v err=%v", certificate, err)
	}
	if _, err := SignServiceClientCSR(authority, makeRequest("aiops-pulse-note", nil), "aiops-pulse-read", time.Unix(0, 0)); err == nil {
		t.Fatal("mismatched service identity was signed")
	}
	if _, err := SignServiceClientCSR(authority, makeRequest("aiops-pulse-read", []string{"aiops-pulse-read.lab.home.arpa"}), "aiops-pulse-read", time.Unix(0, 0)); err == nil {
		t.Fatal("service identity with a DNS SAN was signed")
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
	remainingBlock, _ := pem.Decode(rest)
	if remainingBlock == nil || remainingBlock.Type != "X509 CRL" {
		t.Fatalf("root CRL PEM block = %#v", remainingBlock)
	}
	rootCRL, err := x509.ParseRevocationList(remainingBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	root, err := parseCert(authority.RootCertPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := rootCRL.CheckSignatureFrom(root); err != nil {
		t.Fatalf("root CRL signature did not verify: %v", err)
	}
	if len(rootCRL.RevokedCertificateEntries) != 0 {
		t.Fatalf("root CRL unexpectedly revoked certificates: %#v", rootCRL.RevokedCertificateEntries)
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

func TestSignedServerCertificateUsesServerAuthAndSANs(t *testing.T) {
	authority, err := GenerateAuthority(time.Unix(0, 0), "lab.home.arpa")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "monitor.lab.home.arpa"},
		DNSNames: []string{"monitor.lab.home.arpa", "lab-monitor-01.lab.home.arpa"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := SignServerCSR(authority, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: request})), "monitor", "lab.home.arpa", []string{"lab-monitor-01.lab.home.arpa"}, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(certificate.CertPEM))
	if block == nil {
		t.Fatal("server certificate PEM missing")
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.ExtKeyUsage) != 1 || parsed.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("server certificate does not have server auth usage: %v", parsed.ExtKeyUsage)
	}
	if len(parsed.DNSNames) != 2 || parsed.DNSNames[0] != "monitor.lab.home.arpa" {
		t.Fatalf("unexpected server SANs: %v", parsed.DNSNames)
	}
}

func TestValidateCachedCertificateRequiresCurrentIdentityAndLifetime(t *testing.T) {
	now := time.Unix(0, 0)
	authority, err := GenerateAuthority(now, "lab.home.arpa")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "monitor.lab.home.arpa"},
		DNSNames: []string{"monitor.lab.home.arpa", "lab-monitor-01.lab.home.arpa"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	requestPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: request}))
	issued, err := SignServerCSR(authority, requestPEM, "monitor", "lab.home.arpa", []string{"lab-monitor-01.lab.home.arpa"}, now)
	if err != nil {
		t.Fatal(err)
	}
	reused, err := ValidateServerCertificate(authority, issued.ChainPEM, requestPEM, "monitor", "lab.home.arpa", []string{"lab-monitor-01.lab.home.arpa"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if reused.Fingerprint != issued.Fingerprint || reused.ChainPEM != issued.ChainPEM {
		t.Fatalf("validated certificate changed: reused=%#v issued=%#v", reused, issued)
	}

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherRequest, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "monitor.lab.home.arpa"},
		DNSNames: []string{"monitor.lab.home.arpa", "lab-monitor-01.lab.home.arpa"},
	}, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	otherRequestPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: otherRequest}))
	if _, err := ValidateServerCertificate(authority, issued.ChainPEM, otherRequestPEM, "monitor", "lab.home.arpa", []string{"lab-monitor-01.lab.home.arpa"}, now); err == nil {
		t.Fatal("cached certificate with a different CSR key was accepted")
	}
	if _, err := ValidateServerCertificate(authority, issued.ChainPEM, requestPEM, "monitor", "lab.home.arpa", []string{"lab-monitor-01.lab.home.arpa"}, now.AddDate(10, 0, 0).Add(-15*24*time.Hour)); err == nil {
		t.Fatal("cached certificate inside the renewal window was accepted")
	}
}

func TestValidateCachedServiceClientCertificate(t *testing.T) {
	now := time.Unix(0, 0)
	authority, err := GenerateAuthority(now, "lab.home.arpa")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "aiops-pulse-read"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	requestPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: request}))
	issued, err := SignServiceClientCSR(authority, requestPEM, "aiops-pulse-read", now)
	if err != nil {
		t.Fatal(err)
	}
	reused, err := ValidateServiceClientCertificate(authority, issued.ChainPEM, requestPEM, "aiops-pulse-read", now)
	if err != nil {
		t.Fatal(err)
	}
	if reused.Fingerprint != issued.Fingerprint || reused.Serial != issued.Serial {
		t.Fatalf("validated service certificate changed: reused=%#v issued=%#v", reused, issued)
	}
}
