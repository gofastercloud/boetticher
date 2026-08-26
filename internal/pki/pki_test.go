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
	if err != nil || metadata["root_ca_cn"] != "Homelab Root CA" {
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
