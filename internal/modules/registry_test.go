package modules

import (
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func testConfig(mode string) model.SiteConfig {
	return model.ConfigFromSite(model.NewSite("installation", "age1example", mode))
}

func TestDefaultModulesResolveInDeterministicOrder(t *testing.T) {
	site, modules, err := Compose(testConfig(model.GatewayModeManaged))
	if err != nil {
		t.Fatal(err)
	}
	if len(modules) != 4 || modules[0].Definition.Name != "firewall" || modules[1].Definition.Name != "dns" || modules[2].Definition.Name != "logging" || modules[3].Definition.Name != "monitoring" {
		t.Fatalf("unexpected module resolution: %#v", modules)
	}
	if len(site.PlatformComponents()) != 7 {
		t.Fatalf("default composition produced %d platform components", len(site.PlatformComponents()))
	}
	if !IsEnabled(site, "dns") || !IsEnabled(site, "monitoring") || !IsEnabled(site, "firewall") {
		t.Fatalf("default modules were not enabled: %#v", site.Modules)
	}
	if len(site.Declarations) != 4 || site.Declarations[0].Artifact.DefinitionSHA256 == "" {
		t.Fatalf("default module declarations are incomplete: %#v", site.Declarations)
	}
	for _, declaration := range site.Declarations {
		for _, guest := range declaration.Guests {
			if guest.Module != declaration.Module || !containsTag(guest.Tags, model.TagModule) || !containsTag(guest.Tags, "module-"+declaration.Module) {
				t.Fatalf("guest ownership contract missing for %s: %#v", declaration.Module, guest)
			}
		}
	}
	dns, ok := findDeclaration(site, "dns")
	if !ok {
		t.Fatal("DNS declaration is missing")
	}
	for _, persistent := range dns.Persistent {
		if persistent.Replacement != "retain-across-rootfs-replacement" {
			t.Fatalf("persistent DNS state lacks replacement policy: %#v", persistent)
		}
	}
	for _, secret := range dns.Secrets {
		if secret.Consumer == "kea-dhcp-ddns-server" && secret.Delivery != "systemd-credential-to-ephemeral-secret-file" {
			t.Fatalf("Kea secret delivery is not explicit: %#v", secret)
		}
		if secret.Consumer == "powerdns-authoritative" && (!secret.Persistent || secret.Delivery != "protected-powerdns-backend") {
			t.Fatalf("PowerDNS secret exception is not explicit: %#v", secret)
		}
	}
}

func findDeclaration(site model.Site, name string) (model.ModuleDeclaration, bool) {
	for _, declaration := range site.Declarations {
		if declaration.Module == name {
			return declaration, true
		}
	}
	return model.ModuleDeclaration{}, false
}

func containsTag(tags []string, wanted string) bool {
	for _, tag := range tags {
		if tag == wanted {
			return true
		}
	}
	return false
}

func TestMonitoringCanBeDisabledWithoutRemovingOtherModules(t *testing.T) {
	config := testConfig(model.GatewayModeManaged)
	disabled := false
	config.Modules = map[string]model.ModuleConfig{"monitoring": {Enabled: &disabled}}
	site, _, err := Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	if IsEnabled(site, "monitoring") {
		t.Fatal("monitoring remained enabled")
	}
	for _, component := range site.PlatformComponents() {
		if component.Name == "lab-monitor-01" {
			t.Fatal("disabled monitoring guest remained active")
		}
	}
	if !IsEnabled(site, "dns") || !IsEnabled(site, "firewall") {
		t.Fatal("disabling monitoring changed unrelated module state")
	}
}

func TestDNSCannotBeDisabled(t *testing.T) {
	config := testConfig(model.GatewayModeManaged)
	disabled := false
	config.Modules = map[string]model.ModuleConfig{"dns": {Enabled: &disabled}}
	_, _, err := Compose(config)
	if err == nil || !strings.Contains(err.Error(), "modules.dns.enabled") {
		t.Fatalf("unexpected DNS disable result: %v", err)
	}
}

func TestExternalGatewayRequiresExplicitManagedFirewallDisable(t *testing.T) {
	config := testConfig(model.GatewayModeExternal)
	if _, _, err := Compose(config); err == nil || !strings.Contains(err.Error(), "modules.firewall.enabled") {
		t.Fatalf("external mode without explicit firewall disable was accepted: %v", err)
	}
	disabled := false
	config.Modules = map[string]model.ModuleConfig{"firewall": {Enabled: &disabled}}
	site, _, err := Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	if IsEnabled(site, "firewall") {
		t.Fatal("external mode retained managed firewall")
	}
	for _, component := range site.PlatformComponents() {
		if component.Name == "lab-fw-01" {
			t.Fatal("external mode retained firewall component")
		}
	}
}

func TestUnknownModuleIsRejected(t *testing.T) {
	config := testConfig(model.GatewayModeManaged)
	config.Modules = map[string]model.ModuleConfig{"not-real": {}}
	_, _, err := Compose(config)
	if err == nil || !strings.Contains(err.Error(), "modules.not-real") {
		t.Fatalf("unknown module was accepted: %v", err)
	}
}

func TestDependenciesActivateTransitivelyInStableOrder(t *testing.T) {
	registry := NewRegistry([]ModuleDefinition{
		{Name: "base", Version: "1.0.0", Policy: DefaultOff, Provides: []Capability{"base"}},
		{Name: "service", Version: "1.0.0", Policy: DefaultOff, DependsOn: []string{"base"}, Requires: []Capability{"base"}},
	})
	service := true
	resolved, err := registry.Resolve(model.SiteConfig{Modules: map[string]model.ModuleConfig{"service": {Enabled: &service}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 2 || resolved[0].Definition.Name != "base" || resolved[0].Reason != "dependency" || resolved[1].Definition.Name != "service" {
		t.Fatalf("unexpected dependency resolution: %#v", resolved)
	}
}

func TestDependencyCycleIsRejected(t *testing.T) {
	registry := NewRegistry([]ModuleDefinition{
		{Name: "a", Version: "1.0.0", Policy: DefaultOff, DependsOn: []string{"b"}},
		{Name: "b", Version: "1.0.0", Policy: DefaultOff, DependsOn: []string{"a"}},
	})
	enabled := true
	_, err := registry.Resolve(model.SiteConfig{Modules: map[string]model.ModuleConfig{"a": {Enabled: &enabled}}})
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("dependency cycle was accepted: %v", err)
	}
}
