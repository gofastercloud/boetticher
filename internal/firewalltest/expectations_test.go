package firewalltest

import "testing"

func TestReferenceExpectationsAreRendererIndependent(t *testing.T) {
	expectations := ReferenceExpectations()
	if len(expectations) != 41 {
		t.Fatalf("expectation count = %d, want 41", len(expectations))
	}
	for _, expectation := range expectations {
		if expectation.Expected != "allow" && expectation.Expected != "deny" {
			t.Fatalf("expectation %s has invalid outcome %q", expectation.Name, expectation.Expected)
		}
	}
}

func TestFixturesUseReservedCandidateRange(t *testing.T) {
	zones := []Zone{{Name: "SERVERS", Subnet: "10.10.20.0/24", Gateway: "10.10.20.1"}}
	fixtures, err := Fixtures(zones)
	if err != nil {
		t.Fatal(err)
	}
	if fixtures[0].Address != "10.10.20.250" {
		t.Fatalf("fixture address = %s, want .250", fixtures[0].Address)
	}
	candidates, err := CandidateAddresses("10.10.20.0/24")
	if err != nil || len(candidates) != 5 || candidates[4] != "10.10.20.254" {
		t.Fatalf("candidate addresses = %#v, %v", candidates, err)
	}
}
