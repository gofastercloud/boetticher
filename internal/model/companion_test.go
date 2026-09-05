package model

import "testing"

func TestCompanionBlinktIsOptInAndCloned(t *testing.T) {
	enabled := true
	config := &CompanionConfig{Enabled: &enabled, EthernetMAC: "dc:a6:32:e9:dd:82"}
	if config.Capabilities().Blinkt {
		t.Fatal("Blinkt enabled without selection")
	}
	config.Blinkt = &CompanionCapabilityConfig{Enabled: &enabled}
	copy := cloneCompanionConfig(config)
	*copy.Blinkt.Enabled = false
	if !config.Capabilities().Blinkt || copy.Capabilities().Blinkt {
		t.Fatal("capability copies share mutable pointers")
	}
	config.StreamDeckSerial = "bad\"serial"
	if validateCompanion(config) == nil {
		t.Fatal("unsafe serial accepted")
	}
}

func TestCompanionNewFieldsRoundTrip(t *testing.T) {
	config, err := ParseSiteConfig([]byte("api_version: boetticher/v3\ncompanion:\n  ethernet_mac: dc:a6:32:e9:dd:82\n  streamdeck_serial: ABC123\n  blinkt:\n    enabled: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !config.Companion.Capabilities().Blinkt || config.Companion.StreamDeckSerial != "ABC123" {
		t.Fatal("new configuration fields were not read")
	}
	data, err := RenderSiteConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSiteConfig(data); err != nil {
		t.Fatal(err)
	}
}
