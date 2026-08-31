package cli

import (
	"testing"

	"github.com/gofastercloud/boetticher/internal/firewall"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/networktest"
)

func TestProbeAddressModeUsesDHCPOnlyForDynamicZones(t *testing.T) {
	for _, test := range []struct {
		mode string
		want string
	}{
		{mode: "static", want: "manual"},
		{mode: "reservations-only", want: "manual"},
		{mode: "dynamic-reservations", want: "dhcp"},
		{mode: "dynamic", want: "dhcp"},
	} {
		if got := probeAddressMode(networktest.Probe{AddressMode: test.mode}); got != test.want {
			t.Errorf("address mode %q = %q, want %q", test.mode, got, test.want)
		}
	}
}

func TestGatewayProbeSkipsManagedTRANSITDiagnosticICMP(t *testing.T) {
	if gatewayProbeExpected("TRANSIT") {
		t.Fatal("TRANSIT gateway ICMP was treated as an expected allow")
	}
	for _, zone := range []string{"INFRA", "SERVERS", "TRUSTED", "SANDBOX", "MGMT"} {
		if !gatewayProbeExpected(zone) {
			t.Fatalf("%s gateway ICMP was not treated as an expected allow", zone)
		}
	}
}

func TestProbeDNSNameRespectsSANDBOXNamespaceIsolation(t *testing.T) {
	if got := probeDNSName("SANDBOX", "lab.home.arpa"); got != "example.com" {
		t.Fatalf("SANDBOX DNS probe name = %q, want example.com", got)
	}
	if got := probeDNSName("TRUSTED", "lab.home.arpa"); got != "portal.lab.home.arpa" {
		t.Fatalf("private-zone DNS probe name = %q, want portal.lab.home.arpa", got)
	}
}

func TestPolicyAllowsHonorsSourceAndDestinationCIDRs(t *testing.T) {
	policy := firewall.Plan{Rules: []firewall.PolicyRule{{
		From: "TRUSTED", To: "INFRA", Action: "allow", Protocol: "tcp", Ports: []string{"443"},
		SourceCIDR: "10.10.30.250/32", DestinationCIDR: "10.10.10.30/32",
	}}}
	if !policyAllows(policy, "TRUSTED", "INFRA", "tcp", 443, "10.10.30.250", "10.10.10.30") {
		t.Fatal("matching source and destination was denied")
	}
	if policyAllows(policy, "TRUSTED", "INFRA", "tcp", 443, "10.10.30.251", "10.10.10.30") {
		t.Fatal("non-matching source CIDR was allowed")
	}
}

func TestPolicyAllowsBuiltInHTTPSForDynamicTrustedProbeAddress(t *testing.T) {
	plan, err := firewall.PlanFromSite(model.NewDefaultSite("installation", "age1example"))
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"10.10.30.106", "10.10.30.199"} {
		if !policyAllows(plan, "TRUSTED", "INFRA", "tcp", 443, address, "10.10.10.20") {
			t.Fatalf("Pulse HTTPS was denied for dynamic TRUSTED probe address %s", address)
		}
	}
}
