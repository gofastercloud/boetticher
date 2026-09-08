package firewallmodule

import (
	"strings"
	"testing"
)

func TestParseFirewallSafetyStatusRequiresFixedMarker(t *testing.T) {
	ok, err := parseFirewallSafetyStatus([]byte(`{"exitcode":0,"out-data":"BOETTICHER_SAFETY_OK\n"}`))
	if err != nil || !ok {
		t.Fatalf("valid safety status = %v, %v", ok, err)
	}
	if ok, err := parseFirewallSafetyStatus([]byte(`{"exitcode":1,"out-data":"BOETTICHER_SAFETY_OK"}`)); err != nil || ok {
		t.Fatalf("failed command accepted: %v, %v", ok, err)
	}
	if _, err := parseFirewallSafetyStatus([]byte(`{"out-data":"BOETTICHER_SAFETY_OK"}`)); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("missing exit code not rejected: %v", err)
	}
	if _, err := parseFirewallSafetyStatus([]byte(`{"exitcode":0,"out-data":"ok"}`)); err == nil || !strings.Contains(err.Error(), "success marker") {
		t.Fatalf("wrong marker not rejected: %v", err)
	}
}
