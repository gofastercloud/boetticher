package cli

import "testing"

func TestParseGatewayStatus(t *testing.T) {
	status, err := parseGatewayStatus("forwarding=1\nservice.nftables=active\nservice.kea-dhcp4-server=active\nservice.kea-dhcp-ddns-server=active\nservice.dnsmasq=active\niface.wan0=wan0 UP 192.0.2.10/24\niface.trusted0=trusted0 UP 10.10.30.1/24\niface.servers0=servers0 UP 10.10.20.1/24\niface.sandbox0=sandbox0 UP 10.10.40.1/24\niface.mgmt0=mgmt0 UP 10.10.99.1/24\niface.transit0=transit0 UP 10.10.5.1/24\niface.infra0=infra0 UP 10.10.10.1/24\n")
	if err != nil {
		t.Fatal(err)
	}
	if status.Forwarding != "1" || status.Services["nftables"] != "active" || status.Interfaces["mgmt0"] != "mgmt0 UP 10.10.99.1/24" {
		t.Fatalf("unexpected gateway status: %#v", status)
	}
}

func TestParseGatewayStatusRejectsIncompleteOutput(t *testing.T) {
	if _, err := parseGatewayStatus("forwarding=0\nservice.nftables=inactive\n"); err == nil {
		t.Fatal("incomplete gateway status was accepted")
	}
}

func TestGatewayStatusScriptDoesNotDependOnInterfaceEnumeration(t *testing.T) {
	for _, role := range []string{"wan0", "trusted0", "servers0", "sandbox0", "mgmt0", "transit0", "infra0"} {
		if !containsString(gatewayStatusScript, role) {
			t.Fatalf("gateway status script does not inspect stable role interface %q", role)
		}
	}
}

func containsString(value, wanted string) bool {
	for i := 0; i+len(wanted) <= len(value); i++ {
		if value[i:i+len(wanted)] == wanted {
			return true
		}
	}
	return false
}
