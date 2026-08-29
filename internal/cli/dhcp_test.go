package cli

import (
	"testing"
)

func TestValidateDHCPServicesRequiresBothActiveKeaServices(t *testing.T) {
	valid := gatewayLiveStatus{Services: map[string]string{
		"kea-dhcp4-server":     "active",
		"kea-dhcp-ddns-server": "active",
	}}
	if err := validateDHCPServices(valid); err != nil {
		t.Fatal(err)
	}
	cases := []gatewayLiveStatus{
		{Services: map[string]string{"kea-dhcp4-server": "active"}},
		{Services: map[string]string{"kea-dhcp4-server": "inactive", "kea-dhcp-ddns-server": "active"}},
		{Services: map[string]string{"kea-dhcp4-server": "active", "kea-dhcp-ddns-server": "failed"}},
	}
	for _, value := range cases {
		if err := validateDHCPServices(value); err == nil {
			t.Fatalf("invalid service state was accepted: %#v", value)
		}
	}
}

func TestDHCPStatusParserKeepsGatewayServiceEvidence(t *testing.T) {
	status, err := parseGatewayStatus("forwarding=1\nservice.nftables=active\nservice.kea-dhcp4-server=active\nservice.kea-dhcp-ddns-server=active\nservice.dnsmasq=inactive\niface.wan0=wan0 UP 192.0.2.10/24\niface.trusted0=trusted0 UP 10.10.30.1/24\niface.servers0=servers0 UP 10.10.20.1/24\niface.sandbox0=sandbox0 UP 10.10.40.1/24\niface.mgmt0=mgmt0 UP 10.10.99.1/24\niface.transit0=transit0 UP 10.10.5.1/24\niface.infra0=infra0 UP 10.10.10.1/24\nupstream.interface=wan0\nupstream.mac=02:00:00:00:01:01\nupstream.address=192.0.2.10/24\nupstream.gateway=192.0.2.1\n")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDHCPServices(status); err != nil {
		t.Fatal(err)
	}
	if status.Services["kea-dhcp-ddns-server"] != "active" || status.Upstream.Address == "" {
		t.Fatalf("live gateway evidence was incomplete: %#v", status)
	}
}

func TestDHCPStatusParserRejectsDuplicateEvidence(t *testing.T) {
	_, err := parseGatewayStatus("forwarding=1\nforwarding=1\n")
	if err == nil {
		t.Fatal("duplicate gateway evidence was accepted")
	}
}
