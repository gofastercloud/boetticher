package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"

	"github.com/gofastercloud/boetticher/internal/pathguard"
	"github.com/gofastercloud/boetticher/internal/pki"
)

func TestSignOrReuseServerCertificateCachesOnlyReusablePublicChain(t *testing.T) {
	now := time.Now().UTC()
	authority, err := pki.GenerateAuthority(now, "lab.home.arpa")
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
	cacheDir := t.TempDir()
	first, err := signOrReuseServerCertificate(authority, requestPEM, cacheDir, "monitor", "monitor", "lab.home.arpa", []string{"lab-monitor-01.lab.home.arpa"})
	if err != nil {
		t.Fatal(err)
	}
	cached, err := pathguard.ReadFile(managedCertificateCachePath(cacheDir, "monitor"))
	if err != nil {
		t.Fatal(err)
	}
	if string(cached) != first.ChainPEM {
		t.Fatal("certificate cache does not contain the issued public chain")
	}
	second, err := signOrReuseServerCertificate(authority, requestPEM, cacheDir, "monitor", "monitor", "lab.home.arpa", []string{"lab-monitor-01.lab.home.arpa"})
	if err != nil {
		t.Fatal(err)
	}
	if second.Fingerprint != first.Fingerprint {
		t.Fatalf("second issuance did not reuse cached certificate: first=%s second=%s", first.Fingerprint, second.Fingerprint)
	}
}
