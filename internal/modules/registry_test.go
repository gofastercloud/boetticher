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
	wantOrder := []string{"firewall", "dns", "logging", "monitoring", "aiops", "litellm", "printer", "streamdeck", "tailnet-router"}
	if len(modules) != len(wantOrder) {
		t.Fatalf("unexpected module resolution: %#v", modules)
	}
	for index, name := range wantOrder {
		if modules[index].Definition.Name != name {
			t.Fatalf("module %d = %s, want %s", index, modules[index].Definition.Name, name)
		}
	}
	if len(site.PlatformComponents()) != 7 {
		t.Fatalf("default composition produced %d platform components", len(site.PlatformComponents()))
	}
	if !IsEnabled(site, "dns") || !IsEnabled(site, "monitoring") || !IsEnabled(site, "firewall") {
		t.Fatalf("default modules were not enabled: %#v", site.Modules)
	}
	for _, module := range modules {
		if !module.Enabled {
			continue
		}
		if module.State != "Enabled" {
			t.Fatalf("active module %s reported unexpected desired state %q", module.Definition.Name, module.State)
		}
	}
	if len(site.Declarations) != 4 || site.Declarations[0].Artifact.DefinitionSHA256 == "" {
		t.Fatalf("default module declarations are incomplete: %#v", site.Declarations)
	}
	monitoring, ok := findDeclaration(site, "monitoring")
	if !ok {
		t.Fatal("monitoring declaration is missing")
	}
	var agentToken model.SecretDeclaration
	for _, secret := range monitoring.Secrets {
		if secret.Name == "pulse_agent_token" {
			agentToken = secret
			break
		}
	}
	if agentToken.Consumer != "pulse-agent" || agentToken.Delivery != "systemd-credential" || agentToken.Generation != "ephemeral" {
		t.Fatalf("Pulse agent credential contract is incomplete: %#v", agentToken)
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

func TestNewFirstPartyModulesAreDefaultOffAndReserveNonCollidingIdentity(t *testing.T) {
	registry := FirstPartyRegistry()
	if err := registry.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tailnet-router", "litellm", "streamdeck", "printer", "aiops"} {
		definition, ok := registry.Definition(name)
		if !ok || definition.Policy != DefaultOff {
			t.Fatalf("%s is not a default-off first-party module: %#v", name, definition)
		}
	}
	tailnet, _ := registry.Definition("tailnet-router")
	if tailnet.ReservedVMIDStart != 200 || tailnet.ReservedVMIDEnd != 209 || tailnet.Guests[0].VMID != 200 || tailnet.Placement.ZoneType != model.ZoneTypeTransit {
		t.Fatalf("tailnet-router identity contract is incomplete: %#v", tailnet)
	}
	litellm, _ := registry.Definition("litellm")
	if litellm.ReservedVMIDStart != 210 || litellm.ReservedVMIDEnd != 219 || litellm.Guests[0].VMID != 210 || litellm.Placement.ZoneType != model.ZoneTypeServers {
		t.Fatalf("litellm identity contract is incomplete: %#v", litellm)
	}
	streamdeck, _ := registry.Definition("streamdeck")
	if streamdeck.ReservedVMIDStart != 220 || streamdeck.ReservedVMIDEnd != 229 || streamdeck.Guests[0].VMID != model.StreamDeckVMID || streamdeck.Placement.ZoneType != model.ZoneTypeServers {
		t.Fatalf("streamdeck identity contract is incomplete: %#v", streamdeck)
	}
	printer, _ := registry.Definition("printer")
	if printer.ReservedVMIDStart != 230 || printer.ReservedVMIDEnd != 239 || printer.Guests[0].VMID != model.PrinterVMID || printer.Placement.ZoneType != model.ZoneTypeServers {
		t.Fatalf("printer identity contract is incomplete: %#v", printer)
	}
	aiops, _ := registry.Definition("aiops")
	if aiops.ReservedVMIDStart != 240 || aiops.ReservedVMIDEnd != 249 || aiops.Guests[0].VMID != 240 || aiops.Guests[0].Address != "10.10.20.90" || aiops.Placement.ZoneType != model.ZoneTypeServers {
		t.Fatalf("aiops identity contract is incomplete: %#v", aiops)
	}
}

func TestAIOpsRequiresDeclaredLiteLLMAliasAndComposesReadOnlyBoundary(t *testing.T) {
	config := testConfig(model.GatewayModeManaged)
	enabled := true
	config.Modules.AIOps = &model.AIOpsModuleConfig{Enabled: &enabled, ModelAlias: "operations-investigator"}
	config.Modules.LiteLLM = &model.LiteLLMModuleConfig{
		Upstreams: []model.LiteLLMUpstreamConfig{{Name: "provider", BaseURL: "https://provider.example/v1", APIKeySecret: "provider_api_key"}},
		Models:    []model.LiteLLMModelConfig{{Alias: "operations-investigator", Upstream: "provider", Model: "provider/model"}},
	}
	site, _, err := Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	declaration, ok := findDeclaration(site, "aiops")
	if !ok {
		t.Fatal("aiops declaration is missing")
	}
	if declaration.Guests[0].Address != "10.10.20.90" || declaration.Guests[0].Role != "HolmesGPT AIOps investigation" {
		t.Fatalf("unexpected aiops guest: %#v", declaration.Guests[0])
	}
	if len(declaration.Volumes) != 2 || declaration.Volumes[1].Name != "aiops-state" || declaration.Volumes[1].SizeGiB != 1 {
		t.Fatalf("unexpected aiops volumes: %#v", declaration.Volumes)
	}
	for _, intent := range declaration.NetworkIntents {
		if intent.Ports[0] == "22" || strings.Contains(intent.Endpoint, "internet") {
			t.Fatalf("aiops declaration acquired forbidden SSH/Internet authority: %#v", intent)
		}
	}
	if got := site.ModuleConfig["aiops"].ModelAlias; got != "operations-investigator" {
		t.Fatalf("aiops alias = %q", got)
	}
}

func TestAIOpsRejectsUndeclaredAliasAndExplicitlyDisabledDependency(t *testing.T) {
	config := testConfig(model.GatewayModeManaged)
	enabled, disabled := true, false
	config.Modules.AIOps = &model.AIOpsModuleConfig{Enabled: &enabled, ModelAlias: "missing"}
	config.Modules.LiteLLM = &model.LiteLLMModuleConfig{Upstreams: []model.LiteLLMUpstreamConfig{{Name: "provider", BaseURL: "https://provider.example/v1", APIKeySecret: "provider_api_key"}}, Models: []model.LiteLLMModelConfig{{Alias: "other", Upstream: "provider", Model: "provider/model"}}}
	if _, _, err := Compose(config); err == nil || !strings.Contains(err.Error(), "undeclared LiteLLM model alias") {
		t.Fatalf("undeclared alias was accepted: %v", err)
	}
	config.Modules.LiteLLM.Enabled = &disabled
	config.Modules.AIOps.ModelAlias = "other"
	if _, _, err := Compose(config); err == nil || !strings.Contains(err.Error(), "explicitly disabled") {
		t.Fatalf("disabled dependency was accepted: %v", err)
	}
}

func TestPrinterComposesMinimalOctoPrintDeclaration(t *testing.T) {
	config := testConfig(model.GatewayModeManaged)
	enabled := true
	config.Modules.Printer = &model.ToggleModuleConfig{Enabled: &enabled}
	config.USBExports = []model.USBExportBinding{{Module: "printer", Requirement: "serial", Port: "1-2.4", VendorID: "1a86", ProductID: "7523"}}
	site, _, err := Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	printer, ok := findDeclaration(site, "printer")
	if !ok {
		t.Fatal("printer declaration is missing")
	}
	if len(printer.Guests) != 1 || printer.Guests[0].Address != "10.10.20.80" || printer.Guests[0].URL != "https://octoprint."+site.Network.Domain || !printer.Guests[0].MTLS {
		t.Fatalf("printer guest contract is incomplete: %#v", printer.Guests)
	}
	if !printer.Security.Unprivileged || len(printer.USBRequirements) != 1 || printer.USBRequirements[0].DeviceType != "serial" {
		t.Fatalf("printer USB security contract is incomplete: %#v", printer)
	}
	foundState, foundTLS := false, false
	for _, state := range printer.Persistent {
		foundState = foundState || state.Path == "/var/lib/octoprint" && state.Sensitive && state.Backup
		foundTLS = foundTLS || state.Path == "/var/lib/boetticher/identity/tls" && state.Sensitive && state.Backup
	}
	if !foundState || !foundTLS {
		t.Fatalf("printer persistent state contract is incomplete: %#v", printer.Persistent)
	}
	if len(printer.Secrets) != 0 {
		t.Fatalf("printer declaration invented controller-owned secrets: %#v", printer.Secrets)
	}
}

func TestRegistryRejectsUnsupportedUSBDeviceType(t *testing.T) {
	registry := NewRegistry([]ModuleDefinition{{
		Name: "bad-usb", Version: "1.0.0", Policy: DefaultOff,
		GuestIDs: []int{240}, ReservedVMIDStart: 240, ReservedVMIDEnd: 249,
		Guests:          []model.Component{{Name: "bad-usb", VMID: 240, Address: "10.10.20.90"}},
		USBRequirements: []model.USBRequirement{{Name: "device", Guest: "bad-usb", DeviceType: "block", Access: "rw", Required: true, AllowedIdentities: []model.USBIdentity{{VendorID: "1234", ProductID: "5678"}}}},
	}})
	if err := registry.Validate(); err == nil || !strings.Contains(err.Error(), "USB device type") {
		t.Fatalf("unsupported USB device type was accepted: %v", err)
	}
}

func TestTailnetAndLiteLLMComposeTypedDeclarations(t *testing.T) {
	config := testConfig(model.GatewayModeManaged)
	tailnetEnabled, litellmEnabled := true, true
	config.Modules.TailnetRouter = &model.ToggleModuleConfig{Enabled: &tailnetEnabled}
	config.Modules.LiteLLM = &model.LiteLLMModuleConfig{
		Enabled:   &litellmEnabled,
		Upstreams: []model.LiteLLMUpstreamConfig{{Name: "openrouter", BaseURL: "https://openrouter.ai/api/v1", APIKeySecret: "openrouter_api_key"}},
		Models:    []model.LiteLLMModelConfig{{Alias: "selected-alias", Upstream: "openrouter", Model: "selected/openrouter-model"}},
	}
	site, _, err := Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	tailnet, ok := findDeclaration(site, "tailnet-router")
	if !ok {
		t.Fatal("tailnet-router declaration is missing")
	}
	if tailnet.Guests[0].Zone != "TRANSIT" || tailnet.Guests[0].Address != "10.10.5.10" || !tailnet.Security.Unprivileged || tailnet.Security.Devices[0].Path != "/dev/net/tun" || tailnet.AdvertisedRoutes[0] != "10.10.0.0/16" {
		t.Fatalf("tailnet-router declaration is incomplete: %#v", tailnet)
	}
	litellm, ok := findDeclaration(site, "litellm")
	if !ok {
		t.Fatal("litellm declaration is missing")
	}
	if litellm.Guests[0].Address != "10.10.20.60" || !litellm.Guests[0].MTLS || len(litellm.Secrets) != 1 || litellm.Secrets[0].Name != "openrouter_api_key" {
		t.Fatalf("litellm declaration is incomplete: %#v", litellm)
	}
}

func TestModuleDeclarationsProjectDefinitionsDirectly(t *testing.T) {
	base := testConfig(model.GatewayModeManaged).BaseSite()
	definition, ok := FirstPartyRegistry().Definition("dns")
	if !ok {
		t.Fatal("DNS definition is missing")
	}
	declaration, err := declarationFor(definition, base)
	if err != nil {
		t.Fatal(err)
	}
	if len(declaration.Guests) != len(definition.Guests) {
		t.Fatalf("DNS declaration has %d guests, want %d", len(declaration.Guests), len(definition.Guests))
	}
	for index, guest := range declaration.Guests {
		if guest.Name != definition.Guests[index].Name || guest.VMID != definition.Guests[index].VMID {
			t.Fatalf("declaration guest %d = %#v, want definition guest %#v", index, guest, definition.Guests[index])
		}
		if guest.Module != definition.Name || !containsTag(guest.Tags, model.ModuleOwnershipTag(definition.Name)) {
			t.Fatalf("declaration guest %s lacks generated module ownership: %#v", guest.Name, guest)
		}
	}
}

func TestBaseSiteHasOnlyCoreComponentsBeforeComposition(t *testing.T) {
	base := testConfig(model.GatewayModeManaged).BaseSite()
	for _, component := range base.Components {
		if component.Module != "" {
			t.Fatalf("base site contains module-owned component %s before composition", component.Name)
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
	config.Modules.Monitoring = &model.ToggleModuleConfig{Enabled: &disabled}
	site, _, err := Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	if IsEnabled(site, "monitoring") {
		t.Fatal("monitoring remained enabled")
	}
	for _, module := range site.Modules {
		if module.Name == "monitoring" && module.State != "Disabled" {
			t.Fatalf("disabled monitoring reported unexpected desired state %q", module.State)
		}
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

func TestDNSConfigurationHasNoLifecycleToggle(t *testing.T) {
	var config model.ModulesConfig
	disabled := false
	if err := config.Set("dns", model.ModuleConfig{Enabled: &disabled}); err == nil || !strings.Contains(err.Error(), "modules.dns.enabled") {
		t.Fatalf("DNS lifecycle toggle was accepted: %v", err)
	}
}

func TestLoggingConfigurationHasNoLifecycleToggle(t *testing.T) {
	var config model.ModulesConfig
	disabled := false
	if err := config.Set("logging", model.ModuleConfig{Enabled: &disabled}); err == nil || !strings.Contains(err.Error(), "modules.logging.enabled") {
		t.Fatalf("logging lifecycle toggle was accepted: %v", err)
	}
}

func TestExternalGatewayRequiresExplicitManagedFirewallDisable(t *testing.T) {
	config := testConfig(model.GatewayModeExternal)
	if _, _, err := Compose(config); err == nil || !strings.Contains(err.Error(), "modules.firewall.enabled") {
		t.Fatalf("external mode without explicit firewall disable was accepted: %v", err)
	}
	disabled := false
	config.Modules.Firewall = &model.ToggleModuleConfig{Enabled: &disabled}
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
	_, err := FirstPartyRegistry().resolve(config, map[string]model.ModuleConfig{"not-real": {}})
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
	base := model.NewDefaultSite("test", "age1test")
	resolved, err := registry.resolve(model.ConfigFromSite(base), map[string]model.ModuleConfig{"service": {Enabled: &service}})
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
	base := model.NewDefaultSite("test", "age1test")
	_, err := registry.resolve(model.ConfigFromSite(base), map[string]model.ModuleConfig{"a": {Enabled: &enabled}})
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("dependency cycle was accepted: %v", err)
	}
}
