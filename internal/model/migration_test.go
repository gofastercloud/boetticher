package model

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestMigrateLegacyStreamDeckConfigRemovesOnlyLegacyState(t *testing.T) {
	base := ConfigFromSite(NewSite("installation", "age1example", GatewayModeManaged))
	base.PlatformVersion = "0.4.4"
	data, err := yaml.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	document["modules"] = map[string]any{
		"streamdeck": map[string]any{"enabled": true},
		"printer":    map[string]any{"enabled": true},
	}
	document["usb_exports"] = []any{
		map[string]any{"module": "streamdeck", "requirement": "display", "port": "1-2.5", "vendor_id": "0fd9", "product_id": "006d"},
		map[string]any{"module": "printer", "requirement": "serial", "port": "1-2.4", "vendor_id": "1a86", "product_id": "7523"},
	}
	data, err = yaml.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}

	config, removed, found, err := MigrateLegacyStreamDeckConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	if !found || removed != 1 {
		t.Fatalf("migration result = found %t, removed %d", found, removed)
	}
	if _, ok := config.Modules.Map()["streamdeck"]; ok || len(config.USBExports) != 1 || config.USBExports[0].Module != "printer" {
		t.Fatalf("migration removed unrelated state incorrectly: %#v", config)
	}
	capabilities := config.Companion.Capabilities()
	if capabilities.Enabled || config.Companion == nil {
		t.Fatalf("migration enabled the companion before its Ethernet MAC was recorded: %#v", capabilities)
	}
}

func TestMigrateLegacyStreamDeckConfigRejectsMalformedUSBState(t *testing.T) {
	_, _, _, err := MigrateLegacyStreamDeckConfig([]byte(`api_version: boetticher/v3
modules:
  streamdeck: true
usb_exports: invalid
`))
	if err == nil || !strings.Contains(err.Error(), "usb_exports expected a list") {
		t.Fatalf("malformed USB state was accepted: %v", err)
	}
}
