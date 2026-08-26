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

func TestServerCertificateUsesServerAuthAndSANs(t *testing.T) {
	authority, err := GenerateAuthority(time.Unix(0, 0), "lab.home.arpa")
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := IssueServer(authority, "monitor", "lab.home.arpa", []string{"lab-monitor-01.lab.home.arpa"}, time.Unix(0, 0))
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
