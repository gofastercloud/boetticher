package firewallmodule

import (
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	"github.com/gofastercloud/boetticher/internal/model"
)

func TestManagementACLsUsePreparedControllerBinding(t *testing.T) {
	enabled := true
	modules := clientservices.Modules{DNS: &clientservices.DNSConfig{Enabled: &enabled}, DHCP: &clientservices.DHCPConfig{Enabled: &enabled, Reservations: []clientservices.Reservation{{Name: "lab-companion", Zone: "SERVERS", Address: "10.10.20.61", MAC: "02:00:00:00:14:3d"}}}}
	policy := &CompositionPolicy{ControllerLABAddress: "10.10.20.61", ControllerLABMAC: "02:00:00:00:14:3d"}
	state, err := ComposeAppliance(model.NewSite("lab", "local", model.GatewayModeManaged), modules, policy)
	if err != nil {
		t.Fatal(err)
	}
	var https, ssh bool
	for _, s := range state.Firewall {
		if s.Options["name"] == "Boetticher TRUSTED Proxmox HTTPS" && s.Options["dest_port"] == "443" && s.Options["dest"] == "" && s.Options["src_ip"] == model.ProxmoxManagementAddress+"/32" {
			https = true
		}
		if s.Options["name"] == "Boetticher Controller LAB SSH" && s.Options["src_ip"] == "10.10.20.61/32" && s.Options["src_mac"] == "02:00:00:00:14:3d" && s.Options["dest_ip"] == model.ProxmoxManagementAddress+"/32" && s.Options["dest_port"] == "22" {
			ssh = true
		}
	}
	if !https || !ssh {
		t.Fatalf("management ACLs missing: https=%v ssh=%v", https, ssh)
	}
}

func TestManagementACLBindingFailsClosed(t *testing.T) {
	enabled := true
	base := clientservices.Modules{DNS: &clientservices.DNSConfig{Enabled: &enabled}, DHCP: &clientservices.DHCPConfig{Enabled: &enabled, Reservations: []clientservices.Reservation{{Name: "other", Zone: "SERVERS", Address: "10.10.20.61", MAC: "02:00:00:00:14:3d"}}}}
	for _, policy := range []*CompositionPolicy{{ControllerLABAddress: "10.10.20.61"}, {ControllerLABAddress: "10.10.30.61", ControllerLABMAC: "02:00:00:00:14:3d"}, {ControllerLABAddress: "10.10.20.61", ControllerLABMAC: "02:00:00:00:14:3e"}} {
		if _, err := ComposeAppliance(model.NewSite("lab", "local", model.GatewayModeManaged), base, policy); err == nil {
			t.Fatal("invalid Controller LAB binding accepted")
		}
	}
	state, err := ComposeAppliance(model.NewSite("lab", "local", model.GatewayModeManaged), base, &CompositionPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range state.Firewall {
		if strings.Contains(s.Options["name"], "Controller LAB SSH") {
			t.Fatal("bootstrap composition emitted Controller LAB SSH")
		}
	}
}
