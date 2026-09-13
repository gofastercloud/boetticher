package host

import (
	"errors"
	"github.com/gofastercloud/boetticher/internal/clientservices"
	"net"
	"testing"
)

func TestResolveControllerLABBindingMatchesDownInterfaceAndGlobalMAC(t *testing.T) {
	b := LabConfig{Name: "lab", Proxmox: ProxmoxConfig{Address: "192.168.4.5", User: "root", Repository: "no-subscription"}, Modules: clientservices.Modules{DHCP: &clientservices.DHCPConfig{Reservations: []clientservices.Reservation{{Name: "companion", Zone: "SERVERS", Address: "10.10.20.61", MAC: "00:11:22:33:44:55"}}}}}
	got, err := ResolveControllerLABBinding(b, []net.Interface{{Name: "en9", HardwareAddr: net.HardwareAddr{0, 17, 34, 51, 68, 85}}})
	if err != nil || got.Address != "10.10.20.61" {
		t.Fatalf("binding=%+v err=%v", got, err)
	}
}

func TestResolveControllerLABBindingRejectsMissingAndAmbiguous(t *testing.T) {
	b := LabConfig{Name: "lab", Proxmox: ProxmoxConfig{Address: "192.168.4.5", User: "root", Repository: "no-subscription"}, Modules: clientservices.Modules{DHCP: &clientservices.DHCPConfig{Reservations: []clientservices.Reservation{{Name: "a", Zone: "SERVERS", Address: "10.10.20.61", MAC: "02:11:22:33:44:55"}, {Name: "b", Zone: "SERVERS", Address: "10.10.20.62", MAC: "02:11:22:33:44:55"}}}}}
	_, err := ResolveControllerLABBinding(b, []net.Interface{{HardwareAddr: net.HardwareAddr{2, 17, 34, 51, 68, 85}}})
	if err == nil {
		t.Fatal("ambiguous binding accepted")
	}
	b.Modules.DHCP.Reservations[0].Zone = "TRUSTED"
	b.Modules.DHCP.Reservations[1].Zone = "TRUSTED"
	_, err = ResolveControllerLABBinding(b, []net.Interface{{HardwareAddr: net.HardwareAddr{2, 17, 34, 51, 68, 85}}})
	if !errors.Is(err, ErrNoControllerLABBinding) {
		t.Fatalf("err=%v", err)
	}
}
