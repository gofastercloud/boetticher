package controllerstatus

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadSettingsUsesSmallDefaultsAndReferenceThreshold(t *testing.T) {
	settings, err := LoadSettings(filepath.Join(t.TempDir(), "missing.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if settings.Interval != 30*time.Second || settings.PingInterval != time.Minute || settings.ThroughputInterval != time.Hour || settings.TelemetryInterval != 15*time.Second || settings.HealthyMbps != 500 || !settings.StreamDeckEnabled || settings.StreamDeckBrightness != 0.5 {
		t.Fatalf("unexpected defaults: %#v", settings)
	}
}

func TestLoadSettingsReadsOptionalStatusValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.yml")
	data := []byte("blinkt:\n  enabled: false\n  gpiochip: 2\nstatus:\n  interval: 45s\n  streamdeck:\n    enabled: false\n    brightness: 0.4\n    telemetry_interval: 2m\n    serial: deck-a\n  internet:\n    throughput_interval: 15m\n    healthy_mbps: 250\n  blinkt:\n    enabled: true\n    brightness: 0.2\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	settings, err := LoadSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	if settings.Interval != 45*time.Second || settings.ThroughputInterval != 15*time.Minute || settings.TelemetryInterval != 2*time.Minute || settings.HealthyMbps != 250 || !settings.BlinktEnabled || settings.GPIOChip != 2 || settings.Brightness != 0.2 || settings.StreamDeckEnabled || settings.StreamDeckBrightness != 0.4 || settings.StreamDeckSerial != "deck-a" {
		t.Fatalf("optional status values were not read: %#v", settings)
	}
}
