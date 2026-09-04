package proxmox

import (
	"reflect"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestValidateLegacyStreamDeckIdentityRequiresExactOwnedLXC(t *testing.T) {
	valid := map[string]any{
		"name":     LegacyStreamDeckName,
		"hostname": LegacyStreamDeckName,
		"tags":     "boetticher;managed;module;boetticher-module-streamdeck",
	}
	if err := ValidateLegacyStreamDeckIdentity(KindLXC, valid); err != nil {
		t.Fatalf("valid legacy identity rejected: %v", err)
	}

	tests := []struct {
		name   string
		kind   GuestKind
		mutate func(map[string]any)
	}{
		{name: "wrong kind", kind: KindQEMU},
		{name: "wrong name", kind: KindLXC, mutate: func(config map[string]any) { config["name"] = "unknown-guest" }},
		{name: "wrong hostname", kind: KindLXC, mutate: func(config map[string]any) { config["hostname"] = "unknown-guest" }},
		{name: "missing ownership tag", kind: KindLXC, mutate: func(config map[string]any) { config["tags"] = "boetticher;managed;module" }},
		{name: "empty tags", kind: KindLXC, mutate: func(config map[string]any) { config["tags"] = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := map[string]any{}
			for key, value := range valid {
				config[key] = value
			}
			if test.mutate != nil {
				test.mutate(config)
			}
			if err := ValidateLegacyStreamDeckIdentity(test.kind, config); err == nil {
				t.Fatal("unsafe legacy identity was accepted")
			}
		})
	}
}

func TestLegacyStreamDeckUSBRemovalArgsIsFixedToOwnedVMID(t *testing.T) {
	want := []string{"/usr/lib/boetticher/boetticher-usb-export", "--remove", "220"}
	if got := LegacyStreamDeckUSBRemovalArgs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("LegacyStreamDeckUSBRemovalArgs() = %#v, want %#v", got, want)
	}
	if model.LegacyStreamDeckVMID != 220 {
		t.Fatalf("legacy StreamDeck VMID changed unexpectedly: %d", model.LegacyStreamDeckVMID)
	}
}
