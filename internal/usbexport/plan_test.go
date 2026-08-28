package usbexport

import (
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
)

func TestPlanAssignsDeterministicSlot(t *testing.T) {
	config := model.ConfigFromSite(model.NewDefaultSite("installation", "age1example"))
	enabled := true
	config.Modules.StreamDeck = &model.StreamDeckModuleConfig{Enabled: &enabled}
	config.USBExports = []model.USBExportBinding{{Module: "streamdeck", Requirement: "display", Port: "1-2.3", VendorID: "0fd9", ProductID: "006d"}}
	site, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanFromSite(site)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 1 || plan[0].VMID != 220 || len(plan[0].Exports) != 1 || plan[0].Exports[0].Slot != "dev0" {
		t.Fatalf("unexpected USB plan: %#v", plan)
	}
}

func TestEnabledStreamDeckRequiresBinding(t *testing.T) {
	config := model.ConfigFromSite(model.NewDefaultSite("installation", "age1example"))
	enabled := true
	config.Modules.StreamDeck = &model.StreamDeckModuleConfig{Enabled: &enabled}
	if _, _, err := modules.Compose(config); err == nil {
		t.Fatal("enabled StreamDeck accepted without required USB binding")
	}
}
