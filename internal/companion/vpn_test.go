package companion

import (
	"github.com/gofastercloud/boetticher/internal/model"
	"testing"
	"time"
)

func TestVPNLEDsUseFreshPulseSensors(t *testing.T) {
	now := time.Now()
	one := 1.0
	zero := 0.0
	sensors := []customSensor{}
	for _, check := range model.VPNHealthChecks(true, false) {
		if check.Module == "airvpn" {
			sensors = append(sensors, customSensor{ID: check.ID, Value: &one, Status: "ok", ObservedAt: now})
		}
	}
	state := NewState(Config{AirVPN: true, Tailnet: true})
	state.Update(moduleSensorStatus("airvpn", sensors, now))
	if snapshot := state.Snapshot(); snapshot.LEDs[6].ID != "airvpn" || snapshot.LEDs[6].Status != Healthy || snapshot.LEDs[7].ID != "tailnet-router" || snapshot.Items[6].ID != "agent" {
		t.Fatal("incorrect fixed LED selection")
	}
	sensors[1].Value = &zero
	if moduleSensorStatus("airvpn", sensors, now).Status != Failure {
		t.Fatal("failed handshake did not fail module status")
	}
	sensors[1].Value = &one
	sensors[1].ObservedAt = now.Add(-2 * time.Minute)
	if moduleSensorStatus("airvpn", sensors, now).Status != Waiting {
		t.Fatal("stale handshake was accepted")
	}
	if moduleSensorStatus("airvpn", nil, now).Status != Waiting {
		t.Fatal("missing sensors were accepted")
	}
}
