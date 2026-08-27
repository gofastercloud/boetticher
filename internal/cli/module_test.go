package cli

import (
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
)

func TestModulePurgeSiteReconstructsDisabledModuleWithoutPersistingEnablement(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	disabled := false
	if err := config.Modules.Set("tailnet-router", model.ModuleConfig{Enabled: &disabled}); err != nil {
		t.Fatal(err)
	}
	disabledSite, _, err := modules.Compose(config)
	if err != nil {
		t.Fatal(err)
	}

	purgeSite, err := modulePurgeSite(disabledSite, "tailnet-router")
	if err != nil {
		t.Fatal(err)
	}
	if !modules.IsEnabled(purgeSite, "tailnet-router") {
		t.Fatal("purge reconstruction did not restore the module declaration in memory")
	}
	if got := purgeSite.ModuleConfig["tailnet-router"].Enabled; got == nil || !*got {
		t.Fatal("purge reconstruction did not enable the temporary in-memory module")
	}

	if modules.IsEnabled(disabledSite, "tailnet-router") {
		t.Fatal("purge reconstruction mutated the disabled site")
	}
	if got := disabledSite.ModuleConfig["tailnet-router"].Enabled; got == nil || *got {
		t.Fatal("disabled site was changed while preparing purge")
	}
	for _, declaration := range purgeSite.Declarations {
		if declaration.Module == "tailnet-router" {
			return
		}
	}
	t.Fatal("purge reconstruction omitted the module declaration")
}
