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
	_, err = SignServerCSR(authority, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: request})), "portal", "lab.home.arpa", []string{"lab-portal-01.lab.home.arpa"}, time.Unix(0, 0))
	if err == nil {
		t.Fatal("controller signed a CSR for an unapproved identity")
	}
}

func TestClientNameCannotEscapeRuntimeDirectory(t *testing.T) {
	if err := ValidateClientName("../outside"); err == nil {
		t.Fatal("path traversal client name was accepted")
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
