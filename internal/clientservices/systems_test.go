package clientservices

import (
	"github.com/gofastercloud/boetticher/internal/model"
	"strings"
	"testing"
)

func systemsModules() Modules {
	on := true
	return Modules{DNS: &DNSConfig{Enabled: &on}, DHCP: &DHCPConfig{Enabled: &on, Scopes: DefaultScopes()}, Systems: []System{{Name: "print-server", VMID: 501, Kind: "lxc", GuestName: "print", MAC: "02:00:00:00:20:61", Address: "10.10.20.61", Port: 631}}}
}

func TestSystemsValidateAndExpand(t *testing.T) {
	m := systemsModules()
	if err := Validate(m, model.NewSite("lab", "local", model.GatewayModeManaged)); err != nil {
		t.Fatal(err)
	}
	e := SystemsExpanded(m)
	if e.DHCP == nil || len(e.DHCP.Reservations) != 1 || e.DHCP.Reservations[0].Address != "10.10.20.61" {
		t.Fatalf("expanded=%#v", e.DHCP)
	}
}
func TestSystemsRejectPoolProbeAndExplicitReservation(t *testing.T) {
	for _, address := range []string{"10.10.20.100", "10.10.20.250"} {
		m := systemsModules()
		m.Systems[0].Address = address
		if err := Validate(m, model.NewSite("lab", "local", model.GatewayModeManaged)); err == nil {
			t.Fatalf("accepted %s", address)
		}
	}
	m := systemsModules()
	m.DHCP.Reservations = []Reservation{{Name: "print-server", Zone: "SERVERS", MAC: m.Systems[0].MAC, Address: m.Systems[0].Address}}
	if err := Validate(m, model.NewSite("lab", "local", model.GatewayModeManaged)); err == nil {
		t.Fatal("accepted explicit reservation collision")
	}
}

func TestSystemsDerivedReservationsUseDHCPAndDNSValidation(t *testing.T) {
	site := model.NewSite("lab", "local", model.GatewayModeManaged)
	for name, mutate := range map[string]func(*Modules){
		"DNS collision": func(m *Modules) {
			m.DNS.Records = []DNSRecord{{Name: "print-server", Type: "A", Value: "10.10.20.61"}}
		},
		"platform name":     func(m *Modules) { m.Systems[0].Name = "lab-proxmox-01" },
		"invalid DNS label": func(m *Modules) { m.Systems[0].Name = "print_server" },
	} {
		t.Run(name, func(t *testing.T) {
			m := systemsModules()
			mutate(&m)
			if err := Validate(m, site); err == nil {
				t.Fatalf("derived reservation bypassed validation: %#v", m.Systems[0])
			} else if name == "invalid DNS label" && !strings.Contains(err.Error(), "invalid") {
				t.Fatalf("wrong invalid-label error: %v", err)
			}
		})
	}
}
