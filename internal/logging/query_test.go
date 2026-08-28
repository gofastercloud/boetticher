package logging

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"reflect"
	"testing"
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

type recordingRunner struct {
	name string
	args []string
}

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.name = name
	r.args = args
	return []byte("{}\n"), nil
}
