package cli

import (
	"testing"

	"github.com/gofastercloud/boetticher/internal/firewall"
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
