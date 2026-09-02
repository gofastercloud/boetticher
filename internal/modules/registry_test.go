package modules

import (
	"fmt"
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
	wantOrder := []string{"firewall", "dns", "logging", "monitoring", "aiops", "airvpn", "gatus", "litellm", "printer", "streamdeck", "tailnet-router"}
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
	firewallDeclaration, ok := findDeclaration(site, "firewall")
	if !ok {
		t.Fatal("firewall declaration is missing")
	}
	if !hasPersistentState(firewallDeclaration.Persistent, "firewall-telemetry", "/var/lib/boetticher/firewall-telemetry") || !hasPersistentVolume(firewallDeclaration.Volumes, "firewall-telemetry", "/var/lib/boetticher/firewall-telemetry") {
		t.Fatalf("firewall telemetry persistence contract is incomplete: persistent=%#v volumes=%#v", firewallDeclaration.Persistent, firewallDeclaration.Volumes)
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
	if agentToken.Consumer != "pulse-agent" || agentToken.Delivery != "systemd-credential" || agentToken.Generation != "ephemeral" || agentToken.Lifecycle != model.SecretLifecycleRuntime {
		t.Fatalf("Pulse agent credential contract is incomplete: %#v", agentToken)
	}
	if len(monitoring.NetworkIntents) != 1 || monitoring.NetworkIntents[0].Source != "lab-monitor-01" || monitoring.NetworkIntents[0].Destination != model.LogicalProxmoxIdentity || monitoring.NetworkIntents[0].Protocol != "tcp" || strings.Join(monitoring.NetworkIntents[0].Ports, ",") != "8006" {
		t.Fatalf("Pulse Proxmox API network intent is incomplete: %#v", monitoring.NetworkIntents)
	}
	logging, ok := findDeclaration(site, "logging")
	if !ok {
		t.Fatal("logging declaration is missing")
	}
	var proxmoxLoggingIntent model.NetworkIntent
	for _, intent := range logging.NetworkIntents {
		if intent.Source == model.LogicalProxmoxIdentity {
			proxmoxLoggingIntent = intent
			break
		}
	}
	if proxmoxLoggingIntent.Destination != "logs.lab.home.arpa" || proxmoxLoggingIntent.Protocol != "tcp" || strings.Join(proxmoxLoggingIntent.Ports, ",") != "19532" || proxmoxLoggingIntent.Purpose != "native Proxmox journal upload" {
		t.Fatalf("Proxmox journal upload network intent is incomplete: %#v", proxmoxLoggingIntent)
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

func TestGatusCrossZoneHTTPSIntentsFollowManagedServiceMetadata(t *testing.T) {
	config := testConfig(model.GatewayModeManaged)
	enabled := true
	config.Modules.Gatus = &model.ToggleModuleConfig{Enabled: &enabled}
	site, _, err := Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	gatus, ok := findDeclaration(site, "gatus")
	if !ok {
		t.Fatal("Gatus declaration is missing")
	}
	var gatusMonitorIntent model.NetworkIntent
	for _, intent := range gatus.NetworkIntents {
		if intent.Destination == "lab-monitor-01" {
			gatusMonitorIntent = intent
			break
		}
	}
	if gatusMonitorIntent.Source != "lab-gatus-01" || gatusMonitorIntent.Protocol != "tcp" || strings.Join(gatusMonitorIntent.Ports, ",") != "443" || gatusMonitorIntent.Endpoint != "https://monitor.lab.home.arpa" {
		t.Fatalf("Gatus cross-zone HTTPS intent is incomplete: %#v", gatus.NetworkIntents)
	}
}

func TestGatusInvalidCrossZoneEndpointFailsComposition(t *testing.T) {
	config := testConfig(model.GatewayModeManaged)
	enabled := true
	config.Modules.Gatus = &model.ToggleModuleConfig{Enabled: &enabled}
	site, _, err := Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	for index := range site.Declarations {
		if site.Declarations[index].Module != "monitoring" {
			continue
		}
		for guestIndex := range site.Declarations[index].Guests {
			if site.Declarations[index].Guests[guestIndex].Name == "lab-monitor-01" {
				site.Declarations[index].Guests[guestIndex].URL = "http://monitor.lab.home.arpa"
			}
		}
	}
	if err := addGatusEndpointIntents(&site); err == nil || !strings.Contains(err.Error(), "HTTPS URL") {
		t.Fatalf("invalid Gatus endpoint was accepted: %v", err)
	}
}

func TestNewFirstPartyModulesAreDefaultOffAndReserveNonCollidingIdentity(t *testing.T) {
	registry := FirstPartyRegistry()
	if err := registry.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tailnet-router", "airvpn", "litellm", "printer", "streamdeck", "aiops", "gatus"} {
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
	printer, _ := registry.Definition("printer")
	if printer.ReservedVMIDStart != 230 || printer.ReservedVMIDEnd != 239 || printer.Guests[0].VMID != model.PrinterVMID || printer.Placement.ZoneType != model.ZoneTypeServers {
		t.Fatalf("printer identity contract is incomplete: %#v", printer)
	}
	streamDeck, _ := registry.Definition("streamdeck")
	if streamDeck.ReservedVMIDStart != 220 || streamDeck.ReservedVMIDEnd != 229 || streamDeck.Guests[0].VMID != model.StreamDeckVMID || streamDeck.Guests[0].Address != "10.10.20.70" || streamDeck.Placement.ZoneType != model.ZoneTypeServers || len(streamDeck.USBRequirements) != 1 || streamDeck.USBRequirements[0].DeviceType != "raw-usb" {
		t.Fatalf("streamdeck identity contract is incomplete: %#v", streamDeck)
	}
	aiops, _ := registry.Definition("aiops")
	if aiops.ReservedVMIDStart != 240 || aiops.ReservedVMIDEnd != 249 || aiops.Guests[0].VMID != 240 || aiops.Guests[0].Address != "10.10.20.90" || aiops.Placement.ZoneType != model.ZoneTypeServers {
		t.Fatalf("aiops identity contract is incomplete: %#v", aiops)
	}
	airvpn, _ := registry.Definition("airvpn")
	if airvpn.NetworkCapable || airvpn.ReservedVMIDStart != 260 || airvpn.ReservedVMIDEnd != 269 || airvpn.Guests[0].VMID != model.AirVPNGuestVMID || airvpn.Guests[0].Address != model.AirVPNGuestAddress || airvpn.Placement.ZoneType != model.ZoneTypeTransit {
		t.Fatalf("AirVPN identity contract is incomplete: %#v", airvpn)
	}
	if len(airvpn.Configuration) != 1 || airvpn.Configuration[0].Key != "servers" {
		t.Fatalf("AirVPN configuration contract is incomplete: %#v", airvpn.Configuration)
	}
}

func TestAirVPNNetworkSelectionRequiresExplicitProviderAndOrdersTransitFirst(t *testing.T) {
	config := testConfig(model.GatewayModeManaged)
	clientEnabled, airvpnEnabled := true, false
	config.Modules.LiteLLM = &model.LiteLLMModuleConfig{
		Enabled: &clientEnabled, Network: model.ModuleNetworkAirVPN,
		Upstreams: []model.LiteLLMUpstreamConfig{{Name: "provider", BaseURL: "https://provider.example/v1", APIKeySecret: "provider_api_key"}},
		Models:    []model.LiteLLMModelConfig{{Alias: "selected", Upstream: "provider", Model: "provider/model"}},
	}
	config.Modules.AirVPN = &model.AirVPNModuleConfig{Enabled: &airvpnEnabled, Servers: "europe"}
	if _, _, err := Compose(config); err == nil || !strings.Contains(err.Error(), "modules.litellm.network") {
		t.Fatalf("AirVPN client was accepted without an enabled provider: %v", err)
	}
	airvpnEnabled = true
	site, resolved, err := Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	positions := map[string]int{}
	for index, module := range resolved {
		positions[module.Definition.Name] = index
	}
	if positions["airvpn"] >= positions["litellm"] || site.ModuleConfig["litellm"].Network != model.ModuleNetworkAirVPN {
		t.Fatalf("AirVPN provider was not ordered before its selected client: positions=%v config=%#v", positions, site.ModuleConfig["litellm"])
	}
}

func TestFirstPartyConfigurationFieldsAreTypedAndResolvedFromDeclarations(t *testing.T) {
	registry := FirstPartyRegistry()
	config := testConfig(model.GatewayModeManaged)
	config.Modules.LiteLLM = &model.LiteLLMModuleConfig{
		Upstreams: []model.LiteLLMUpstreamConfig{{Name: "provider", BaseURL: "https://provider.example/v1", APIKeySecret: "provider_key"}},
		Models:    []model.LiteLLMModelConfig{{Alias: "operations", Upstream: "provider", Model: "provider/model"}},
	}
	fields, err := registry.ConfigurationFields("aiops", config)
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 2 || fields[0].Key != "network" || fields[0].Type != model.ModuleConfigEnum || fields[1].Type != model.ModuleConfigModelAlias || len(fields[1].AllowedValues) != 1 || fields[1].AllowedValues[0] != "operations" {
		t.Fatalf("unexpected AIOps configuration schema: %#v", fields)
	}
	litellm, err := registry.ConfigurationFields("litellm", config)
	if err != nil {
		t.Fatal(err)
	}
	if len(litellm) != 3 || litellm[0].Key != "network" || litellm[1].Type != model.ModuleConfigObjectList || litellm[2].Type != model.ModuleConfigObjectList {
		t.Fatalf("unexpected LiteLLM configuration schema: %#v", litellm)
	}
	secretField := model.ModuleConfigField{}
	for _, field := range litellm[1].ItemFields {
		if field.Key == "api_key_secret" {
			secretField = field
		}
	}
	if !secretField.Sensitive {
		t.Fatalf("LiteLLM secret reference is not structurally classified: %#v", litellm[1])
	}
}

func TestRegistryRejectsMalformedConfigurationField(t *testing.T) {
	registry := NewRegistry([]ModuleDefinition{{
		Name: "bad", Version: "1", Policy: DefaultOff,
		Configuration: []model.ModuleConfigField{{Key: "choice", Type: model.ModuleConfigEnum, Prompt: "Choice"}},
	}})
	if err := registry.Validate(); err == nil || !strings.Contains(err.Error(), "enum has no allowed values") {
		t.Fatalf("malformed configuration schema was accepted: %v", err)
	}
}

func TestRegistryRejectsDuplicateModuleDefinitions(t *testing.T) {
	registry := NewRegistry([]ModuleDefinition{
		{Name: "duplicate", Version: "1", Policy: DefaultOff},
		{Name: "duplicate", Version: "2", Policy: DefaultOff},
	})
	if err := registry.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate module definition") {
		t.Fatalf("duplicate module definitions were accepted: %v", err)
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

func TestStreamDeckComposesReadOnlyPulseDisplayDeclaration(t *testing.T) {
	config := testConfig(model.GatewayModeManaged)
	enabled := true
	config.Modules.StreamDeck = &model.ToggleModuleConfig{Enabled: &enabled}
	config.USBExports = []model.USBExportBinding{{Module: "streamdeck", Requirement: "display", Port: "1-2.5", VendorID: "0fd9", ProductID: "006d"}}
	site, _, err := Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	streamDeck, ok := findDeclaration(site, "streamdeck")
	if !ok {
		t.Fatal("StreamDeck declaration is missing")
	}
	if len(streamDeck.Guests) != 1 || streamDeck.Guests[0].Name != "lab-streamdeck-01" || streamDeck.Guests[0].Address != "10.10.20.70" || streamDeck.Guests[0].MTLS {
		t.Fatalf("StreamDeck guest contract is incomplete: %#v", streamDeck.Guests)
	}
	if !streamDeck.Security.Unprivileged || len(streamDeck.USBRequirements) != 1 || streamDeck.USBRequirements[0].DeviceType != "raw-usb" {
		t.Fatalf("StreamDeck USB/security contract is incomplete: %#v", streamDeck)
	}
	var pulseToken model.SecretDeclaration
	for _, secret := range streamDeck.Secrets {
		if secret.Name == "pulse_api_token" {
			pulseToken = secret
		}
	}
	if pulseToken.Consumer != "streamdeck-status" || pulseToken.Delivery != "systemd-credential" || pulseToken.Lifecycle != model.SecretLifecycleRuntime {
		t.Fatalf("StreamDeck Pulse token contract is incomplete: %#v", streamDeck.Secrets)
	}
	if !hasPersistentState(streamDeck.Persistent, "tls-identity", "/var/lib/boetticher/identity/tls") || !hasPersistentVolume(streamDeck.Volumes, "tls-identity", "/var/lib/boetticher/identity/tls") {
		t.Fatalf("StreamDeck TLS persistence contract is incomplete: persistent=%#v volumes=%#v", streamDeck.Persistent, streamDeck.Volumes)
	}
	if len(streamDeck.Persistent) != 2 || len(streamDeck.Volumes) != 2 {
		t.Fatalf("StreamDeck persistence contract contains unexpected entries: persistent=%#v volumes=%#v", streamDeck.Persistent, streamDeck.Volumes)
	}
	if len(streamDeck.Certificates) != 2 || streamDeck.Certificates[1].Identity != "lab-streamdeck-01" || len(streamDeck.NetworkIntents) != 3 {
		t.Fatalf("StreamDeck mTLS/network declaration is incomplete: certificates=%#v intents=%#v", streamDeck.Certificates, streamDeck.NetworkIntents)
	}
	if len(streamDeck.Monitoring) != 2 || streamDeck.Monitoring[1].Name != "streamdeck-status" {
		t.Fatalf("StreamDeck monitoring declaration is incomplete: %#v", streamDeck.Monitoring)
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

func TestTailnetDeclarationCoversTailscaleDERPRegions(t *testing.T) {
	config := testConfig(model.GatewayModeManaged)
	enabled := true
	config.Modules.TailnetRouter = &model.ToggleModuleConfig{Enabled: &enabled}
	site, _, err := Compose(config)
	if err != nil {
		t.Fatal(err)
	}
	tailnet, ok := findDeclaration(site, "tailnet-router")
	if !ok {
		t.Fatal("tailnet-router declaration is missing")
	}
	want := make(map[string]bool, 28)
	for region := 1; region <= 28; region++ {
		want[fmt.Sprintf("https://derp%d-all.tailscale.com", region)] = false
	}
	for _, intent := range tailnet.NetworkIntents {
		if _, ok := want[intent.Endpoint]; !ok {
			continue
		}
		if intent.Source != "lab-tailnet-01" || intent.Protocol != "tcp" || strings.Join(intent.Ports, ",") != "443" || intent.Direction != "egress" {
			t.Fatalf("DERP intent is incomplete: %#v", intent)
		}
		want[intent.Endpoint] = true
	}
	for endpoint, found := range want {
		if !found {
			t.Errorf("tailnet declaration is missing DERP endpoint %s", endpoint)
		}
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

func hasPersistentState(states []model.PersistentState, name, path string) bool {
	for _, state := range states {
		if state.Name == name && state.Path == path && state.Backup && state.Replacement == "retain-across-rootfs-replacement" {
			return true
		}
	}
	return false
}

func hasPersistentVolume(volumes []model.PersistentVolumeDeclaration, name, path string) bool {
	for _, volume := range volumes {
		if volume.Name == name && volume.MountPath == path && volume.Backup {
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

func TestMonitoringDeclaresOperatorSuppliedPulseProxySecret(t *testing.T) {
	site, _, err := Compose(testConfig(model.GatewayModeManaged))
	if err != nil {
		t.Fatal(err)
	}
	declaration, ok := findDeclaration(site, "monitoring")
	if !ok {
		t.Fatal("monitoring declaration is missing")
	}
	for _, secret := range declaration.Secrets {
		if secret.Name != "pulse_proxy_auth_secret" {
			continue
		}
		if secret.Generation != "operator-supplied" || secret.Delivery != "systemd-credential" || secret.Consumer != "pulse-server/nginx" || secret.Lifecycle != model.SecretLifecycleRuntime {
			t.Fatalf("Pulse proxy-auth secret contract is incomplete: %#v", secret)
		}
		return
	}
	t.Fatal("monitoring declaration does not include pulse_proxy_auth_secret")
}
