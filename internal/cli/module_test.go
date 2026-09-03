package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
	"github.com/gofastercloud/boetticher/internal/site"
)

func TestModuleChangeSavesDesiredStateWithoutImplicitDeployment(t *testing.T) {
	dir := t.TempDir()
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	if err := site.SaveConfig(dir, config); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := runModuleChangeWithInput([]string{"monitoring", "--site", dir, "--confirm"}, strings.NewReader(""), &output, &output, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Deployment: pending") {
		t.Fatalf("module change did not report pending deployment: %s", output.String())
	}
	if strings.Contains(output.String(), "deploy module change") {
		t.Fatalf("module change still attempted an implicit deployment: %s", output.String())
	}

	updated, err := site.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	module, ok := findResolvedModule(updated, "monitoring")
	if !ok || module.Enabled {
		t.Fatalf("monitoring was not disabled in desired state: %#v", updated.Modules)
	}
	if len(updated.RetainedModules) != 1 || updated.RetainedModules[0].Module != "monitoring" {
		t.Fatalf("disable did not preserve retained module state: %#v", updated.RetainedModules)
	}
}

func TestModulePurgeRecordsOfflinePendingOperation(t *testing.T) {
	dir := t.TempDir()
	config := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	if err := site.SaveConfig(dir, config); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := runModuleChangeWithInput([]string{"monitoring", "--site", dir, "--purge", "--confirm"}, strings.NewReader(""), &output, &output, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Purge: pending deployment") {
		t.Fatalf("module purge did not report a pending operation: %s", output.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "generated", "purge-intent.json")); err != nil {
		t.Fatal(err)
	}
	intent, found, err := site.LoadPurgeIntent(dir)
	if err != nil || !found || intent.Module != "monitoring" || len(intent.Guests) != 1 {
		t.Fatalf("unexpected pending purge: %#v, %v, found=%t", intent, err, found)
	}
	updated, err := site.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.RetainedModules) != 0 {
		t.Fatalf("purge retained resources instead of recording operation: %#v", updated.RetainedModules)
	}
}

func TestApplyModuleStateRejectsInvalidRetainedStateBeforeWritingConfig(t *testing.T) {
	dir := t.TempDir()
	original := model.ConfigFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	if err := site.SaveConfig(dir, original); err != nil {
		t.Fatal(err)
	}
	originalBytes, err := os.ReadFile(filepath.Join(dir, "site.yml"))
	if err != nil {
		t.Fatal(err)
	}
	changed := original
	disabled := false
	if err := changed.Modules.Set("monitoring", model.ModuleConfig{Enabled: &disabled}); err != nil {
		t.Fatal(err)
	}
	invalidRetained := []model.RetainedModule{{Module: "monitoring", Disposition: "retained", Active: true}}
	if err := site.ApplyModuleState(dir, changed, invalidRetained, nil); err == nil {
		t.Fatal("invalid retained state was accepted")
	}
	loadedBytes, err := os.ReadFile(filepath.Join(dir, "site.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(loadedBytes) != string(originalBytes) {
		t.Fatalf("config changed after rejected module operation: got=%s want=%s", loadedBytes, originalBytes)
	}
}

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
