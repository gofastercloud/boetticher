package companion

import (
	"testing"
)

func TestVPNLEDsRemainBoundedWithoutRemoteTelemetry(t *testing.T) {
	state := NewState(Config{AirVPN: true, Tailnet: true})
	if snapshot := state.Snapshot(); snapshot.LEDs[6].ID != "airvpn" || snapshot.LEDs[7].ID != "tailnet-router" || snapshot.Items[4].ID != "proxmox" {
		t.Fatal("incorrect fixed LED selection")
	}
}
