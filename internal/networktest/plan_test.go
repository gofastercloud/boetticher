package networktest

import (
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestPlansUseStableZoneOrderAndAddressModes(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	zones, err := SelectZones(site, "TRUSTED,INFRA,SANDBOX")
	if err != nil {
		t.Fatal(err)
	}
	probes, err := Plans(site, zones, "20260830t010203-a1b2c3")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(probes), 4; got != want {
		t.Fatalf("probe count = %d, want %d", got, want)
	}
	if probes[0].Zone != "INFRA" || probes[0].VMID != VMIDMin || probes[0].Address != "10.10.10.250" || probes[0].AddressMode != "static" {
		t.Fatalf("unexpected INFRA probe: %+v", probes[0])
	}
	if probes[1].Zone != "TRUSTED" || probes[1].Address != "" || probes[1].AddressMode != "dynamic-reservations" {
		t.Fatalf("unexpected TRUSTED probe: %+v", probes[1])
	}
	if probes[2].Zone != "SANDBOX" || probes[2].Address != "" || probes[2].AddressMode != "dynamic" {
		t.Fatalf("unexpected SANDBOX probe: %+v", probes[2])
	}
	if probes[0].MAC != MAC(site.SecretMetadata.InstallationID, "INFRA") {
		t.Fatalf("probe MAC is not deterministic: %s", probes[0].MAC)
	}
}

func TestPlansSkipOccupiedStaticAddresses(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	site.DHCPReservations = append(site.DHCPReservations, model.DHCPReservation{Address: "10.10.10.250"})
	zones, err := SelectZones(site, "INFRA")
	if err != nil {
		t.Fatal(err)
	}
	probes, err := Plans(site, zones, "20260830t010203-a1b2c3")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := probes[0].Address, "10.10.10.251"; got != want {
		t.Fatalf("static address = %s, want %s", got, want)
	}
}

func TestSelectZonesRejectsUnknownZone(t *testing.T) {
	site := model.NewDefaultSite("installation", "age1example")
	if _, err := SelectZones(site, "INFRA,NOT-A-ZONE"); err == nil {
		t.Fatal("unknown zone unexpectedly accepted")
	}
}
