package logging

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/gofastercloud/boetticher/internal/pki"
)

func TestVerifyQueryClientRequiresExactAIOpsIdentity(t *testing.T) {
	if err := VerifyQueryClient(tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: AIOpsLogClientIdentity}}}}); err != nil {
		t.Fatal(err)
	}
	for _, identity := range []string{"operator", "aiops-log-read.attacker", ""} {
		if err := VerifyQueryClient(tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: identity}}}}); err == nil {
			t.Fatalf("identity %q was accepted", identity)
		}
	}
}

func TestVerifyQueryClientWithCRLRejectsOnlyRevokedSerial(t *testing.T) {
	crl := &x509.RevocationList{RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(7)}}}
	valid := tls.ConnectionState{PeerCertificates: []*x509.Certificate{{SerialNumber: big.NewInt(8), Subject: pkix.Name{CommonName: AIOpsLogClientIdentity}}}}
	if err := VerifyQueryClientWithCRL(valid, crl); err != nil {
		t.Fatal(err)
	}
	revoked := valid
	revoked.PeerCertificates = []*x509.Certificate{{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: AIOpsLogClientIdentity}}}
	if err := VerifyQueryClientWithCRL(revoked, crl); err == nil {
		t.Fatal("revoked journal query certificate was accepted")
	}
}

func TestParseVerifiedCRLRequiresTrustedCurrentCRL(t *testing.T) {
	now := time.Date(2026, time.August, 29, 0, 0, 0, 0, time.UTC)
	authority, err := pki.GenerateAuthority(now, "lab.home.arpa")
	if err != nil {
		t.Fatal(err)
	}
	crlPEM, err := pki.GenerateCRL(authority, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseVerifiedCRL(crlPEM, authority.RootCertPEM+authority.IssuingCertPEM, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseVerifiedCRL(crlPEM, authority.RootCertPEM, now.Add(time.Minute)); err == nil {
		t.Fatal("CRL signed by the issuing CA was accepted without the issuing CA")
	}
}

func TestJournalQueryIsTypedAndBounded(t *testing.T) {
	policy := QueryPolicy{Hosts: map[string][]string{"lab-dns-01": {"blocky.service"}}}
	valid := QueryRequest{Host: "lab-dns-01", Unit: "blocky.service", Priority: "warning", SinceMinutes: 120, Limit: 200}
	if err := policy.Validate(valid); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []QueryRequest{{Host: "attacker", SinceMinutes: 1, Limit: 1}, {Host: "lab-dns-01", Unit: "../../etc/shadow", SinceMinutes: 1, Limit: 1}, {Host: "lab-dns-01", SinceMinutes: 121, Limit: 1}, {Host: "lab-dns-01", SinceMinutes: 1, Limit: 201}} {
		if policy.Validate(invalid) == nil {
			t.Fatalf("accepted %#v", invalid)
		}
	}
	want := []string{"--directory=/var/log/journal/remote", "--no-pager", "--output=json", "--since=-120 minutes", "--lines=200", "_HOSTNAME=lab-dns-01", "_SYSTEMD_UNIT=blocky.service", "--priority=warning"}
	if got := QueryArguments(valid); !reflect.DeepEqual(got, want) {
		t.Fatalf("args=%q", got)
	}
}
