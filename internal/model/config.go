package model

import (
	"errors"
	"fmt"
	"net/url"
)

// SiteConfig is the small 0.5 site file you edit. Boetticher builds the
// expanded component list and module details from it, so site.yml stays tidy.
type SiteConfig struct {
	// APIVersion identifies the site-file format.
	APIVersion string `yaml:"api_version" json:"api_version" jsonschema:"const=boetticher/v3" jsonschema_description:"Version marker for this site file."`
	// PlatformVersion is the Boetticher release targeted by this site.
	PlatformVersion string `yaml:"platform_version" json:"platform_version,omitempty" jsonschema:"const=0.5.1" jsonschema_description:"Boetticher platform release targeted by this site."`
	// SchemaVersion identifies the shape of the site file.
	SchemaVersion int `yaml:"schema_version" json:"schema_version,omitempty" jsonschema:"const=3" jsonschema_description:"Shape version of this site file."`
	// StorageProfile chooses the fixed single-disk or dedicated-data-disk layout.
	StorageProfile string `yaml:"storage_profile" json:"storage_profile,omitempty" jsonschema:"enum=single-disk,enum=dedicated-data-disk" jsonschema_description:"Fixed storage layout: the system disk or a separate dedicated data disk."`
	// StorageDevice names the stable device used by the dedicated data layout.
	StorageDevice string `yaml:"storage_device,omitempty" json:"storage_device,omitempty" jsonschema_description:"Stable /dev/disk/by-id identity for dedicated data storage."`
	// Gateway selects the Boetticher gateway or your own external firewall.
	Gateway Gateway `yaml:"gateway" json:"gateway,omitempty" jsonschema_description:"Gateway mode and the existing upstream connection."`
	// BootstrapAddress records the known HOME-side address of the Proxmox host.
	BootstrapAddress string `yaml:"bootstrap_address,omitempty" json:"bootstrap_address,omitempty"`
	// SSHIdentityFile optionally overrides the controller SSH identity.
	SSHIdentityFile string `yaml:"ssh_identity_file,omitempty" json:"ssh_identity_file,omitempty"`
	// PhysicalNetwork records installation-specific NIC bindings separately from the logical network.
	PhysicalNetwork PhysicalNetwork `yaml:"physical_network" json:"physical_network,omitempty" jsonschema_description:"Installation-specific NIC bindings; the logical VLAN architecture is fixed."`
	// TestedVersions records the pinned platform inputs used by this site.
	TestedVersions TestedVersions `yaml:"tested_versions" json:"tested_versions,omitempty"`
	// Network contains the fixed private domain and zone layout.
	Network Network `yaml:"network" json:"network,omitempty" jsonschema_description:"Private domain and fixed network-zone layout."`
	// PKI contains public certificate metadata; private keys remain outside site.yml.
	PKI PKIMetadata `yaml:"pki" json:"pki,omitempty"`
	// SecretMetadata identifies encrypted secrets without storing their values.
	SecretMetadata SecretMetadata `yaml:"secret_metadata" json:"secret_metadata,omitempty"`
	// Ownership records the fixed resource ranges and workload boundary.
	Ownership OwnershipPolicy `yaml:"ownership" json:"ownership,omitempty"`
	// Modules contains typed settings for built-in modules.
	Modules ModulesConfig `yaml:"modules,omitempty" json:"modules,omitempty" jsonschema_description:"Typed settings for built-in modules."`
	// Companion contains the optional capabilities of an external Pi. It is
	// deliberately separate from Modules because it is not a Proxmox workload.
	Companion *CompanionConfig `yaml:"companion,omitempty" json:"companion,omitempty" jsonschema_description:"Optional capabilities of an external Boetticher companion device."`
	// USBExports records stable physical-port bindings for declared module requirements.
	USBExports []USBExportBinding `yaml:"usb_exports,omitempty" json:"usb_exports,omitempty"`
	// DHCPReservations records explicit SERVERS reservations for user workloads.
	DHCPReservations []DHCPReservation `yaml:"dhcp_reservations,omitempty" json:"dhcp_reservations,omitempty"`
	// DNSRecords records user-owned A and CNAME records in the private namespace.
	DNSRecords []UserDNSRecord `yaml:"dns_records,omitempty" json:"dns_records,omitempty"`
	// UserFirewallRules records focused firewall allowances for your workloads.
	UserFirewallRules []UserFirewallRule `yaml:"firewall_rules,omitempty" json:"firewall_rules,omitempty"`
}

// ModulesConfig holds the settings for built-in modules. Each module has a
// typed shape; an internal lookup map is built later for the deploy code.
type ModulesConfig struct {
	DNS           *DNSModuleConfig           `yaml:"dns,omitempty" json:"dns,omitempty"`
	Monitoring    *ToggleModuleConfig        `yaml:"monitoring,omitempty" json:"monitoring,omitempty"`
	Firewall      *ToggleModuleConfig        `yaml:"firewall,omitempty" json:"firewall,omitempty"`
	Logging       *ToggleModuleConfig        `yaml:"logging,omitempty" json:"logging,omitempty"`
	TailnetRouter *ToggleModuleConfig        `yaml:"tailnet-router,omitempty" json:"tailnet-router,omitempty"`
	Bifrost       *BifrostModuleConfig       `yaml:"bifrost,omitempty" json:"bifrost,omitempty"`
	Printer       *NetworkToggleModuleConfig `yaml:"printer,omitempty" json:"printer,omitempty"`
	AIOps         *AIOpsModuleConfig         `yaml:"aiops,omitempty" json:"aiops,omitempty"`
	Gatus         *NetworkToggleModuleConfig `yaml:"gatus,omitempty" json:"gatus,omitempty"`
	AirVPN        *AirVPNModuleConfig        `yaml:"airvpn,omitempty" json:"airvpn,omitempty"`
	Arr           *ArrModuleConfig           `yaml:"arr,omitempty" json:"arr,omitempty"`
}

// CompanionConfig is the fixed capability contract for an external Pi. New
// capability types are intentionally added here rather than through a generic
// daemon or plugin mechanism.
type CompanionConfig struct {
	Enabled    *bool                      `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Display    *CompanionCapabilityConfig `yaml:"display,omitempty" json:"display,omitempty"`
	StreamDeck *CompanionCapabilityConfig `yaml:"streamdeck,omitempty" json:"streamdeck,omitempty"`
	PulseAgent *CompanionCapabilityConfig `yaml:"pulse_agent,omitempty" json:"pulse_agent,omitempty"`
}

type CompanionCapabilityConfig struct {
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
}

type CompanionCapabilities struct {
	Enabled    bool
	Display    bool
	StreamDeck bool
	PulseAgent bool
}

// Capabilities applies one simple rule: a disabled companion disables every
// capability. An omitted companion keeps the pre-0.5 kiosk setup usable while
// sites migrate to the explicit typed section.
func (c *CompanionConfig) Capabilities() CompanionCapabilities {
	if c == nil {
		return CompanionCapabilities{Enabled: true, Display: true, StreamDeck: true, PulseAgent: true}
	}
	enabled := c.Enabled == nil || *c.Enabled
	return CompanionCapabilities{
		Enabled:    enabled,
		Display:    enabled && capabilityEnabled(c.Display),
		StreamDeck: enabled && capabilityEnabled(c.StreamDeck),
		PulseAgent: enabled && capabilityEnabled(c.PulseAgent),
	}
}

func capabilityEnabled(c *CompanionCapabilityConfig) bool {
	return c != nil && (c.Enabled == nil || *c.Enabled)
}

// ModuleNetworkMode selects the Internet route for a module that supports it.
// Empty still means direct so existing v3 site files keep working.
type ModuleNetworkMode string

const (
	ModuleNetworkDirect ModuleNetworkMode = "direct"
	ModuleNetworkAirVPN ModuleNetworkMode = "airvpn"
)

// ModuleConfigField describes one question that module configure can ask. It
// powers the shared setup experience; the typed module structs still hold the
// saved configuration.
type ModuleConfigField struct {
	Key           string                `json:"key"`
	Type          ModuleConfigFieldType `json:"type"`
	Prompt        string                `json:"prompt"`
	Description   string                `json:"description,omitempty"`
	Required      bool                  `json:"required,omitempty"`
	Default       string                `json:"default,omitempty"`
	Sensitive     bool                  `json:"sensitive,omitempty"`
	AllowedValues []string              `json:"allowed_values,omitempty"`
	Resolver      string                `json:"resolver,omitempty"`
	MinItems      int                   `json:"min_items,omitempty"`
	MaxItems      int                   `json:"max_items,omitempty"`
	ItemFields    []ModuleConfigField   `json:"item_fields,omitempty"`
}

type ModuleConfigFieldType string

const (
	ModuleConfigBool       ModuleConfigFieldType = "bool"
	ModuleConfigString     ModuleConfigFieldType = "string"
	ModuleConfigEnum       ModuleConfigFieldType = "enum"
	ModuleConfigModelAlias ModuleConfigFieldType = "model-alias"
	ModuleConfigObjectList ModuleConfigFieldType = "object-list"
)

// DNSModuleConfig is intentionally empty: Blocky is the one built-in DNS
// implementation, so there is no provider selector to configure.
type DNSModuleConfig struct{}

// ToggleModuleConfig is the on/off setting for an optional module without
// application egress configuration.
type ToggleModuleConfig struct {
	// Enabled selects whether an optional module should be deployed.
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
}

// NetworkToggleModuleConfig is the on/off setting for an optional module that
// declares an external egress path.
type NetworkToggleModuleConfig struct {
	// Enabled selects whether an optional module should be deployed.
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	// Network selects the external egress path for network-capable modules.
	Network ModuleNetworkMode `yaml:"network,omitempty" json:"network,omitempty" jsonschema:"enum=direct,enum=airvpn"`
}

// ArrModuleConfig is fixed to AirVPN egress because the *arr services are
// intentionally never allowed to use the direct WAN path.
type ArrModuleConfig struct {
	Enabled *bool             `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Network ModuleNetworkMode `yaml:"network,omitempty" json:"network,omitempty" jsonschema:"enum=airvpn"`
}

// BifrostModuleConfig configures the provider-neutral Bifrost AI endpoint and
// its friendly model aliases.
type BifrostModuleConfig struct {
	// Enabled selects whether the AI router should be deployed.
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	// Network selects the external egress path for the AI router.
	Network ModuleNetworkMode `yaml:"network,omitempty" json:"network,omitempty" jsonschema:"enum=direct,enum=airvpn"`
	// Upstreams declares HTTPS provider endpoints and references to encrypted credentials.
	Upstreams []BifrostUpstreamConfig `yaml:"upstreams,omitempty" json:"upstreams,omitempty"`
	// Models declares the provider-neutral aliases clients may request.
	Models []BifrostModelConfig `yaml:"models,omitempty" json:"models,omitempty"`
}

// BifrostUpstreamConfig names one HTTPS AI provider and its encrypted key.
type BifrostUpstreamConfig struct {
	Name         string `yaml:"name" json:"name"`
	BaseURL      string `yaml:"base_url" json:"base_url"`
	APIKeySecret string `yaml:"api_key_secret" json:"api_key_secret"`
}

// BifrostModelConfig maps a friendly alias to one provider model.
type BifrostModelConfig struct {
	Alias    string `yaml:"alias" json:"alias"`
	Upstream string `yaml:"upstream" json:"upstream"`
	Model    string `yaml:"model" json:"model"`
}

// AIOpsModuleConfig selects the model alias used by the read-only AIOps helper.
type AIOpsModuleConfig struct {
	Enabled    *bool             `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Network    ModuleNetworkMode `yaml:"network,omitempty" json:"network,omitempty" jsonschema:"enum=direct,enum=airvpn"`
	ModelAlias string            `yaml:"model_alias" json:"model_alias"`
}

// AirVPNModuleConfig controls the controller-side AirVPN profile generator.
// The API key lives at the controller-only secret path, never in site.yml.
type AirVPNModuleConfig struct {
	// Enabled turns the optional AirVPN transit guest on or off.
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	// Servers is the AirVPN server selector, such as europe.
	Servers string `yaml:"servers" json:"servers"`
}

// Map returns the normalised internal lookup map. It is not written back as
// the site-file representation.
func (m ModulesConfig) Map() map[string]ModuleConfig {
	result := make(map[string]ModuleConfig)
	if m.DNS != nil {
		result["dns"] = ModuleConfig{}
	}
	if m.Monitoring != nil {
		result["monitoring"] = ModuleConfig{Enabled: cloneBool(m.Monitoring.Enabled)}
	}
	if m.Firewall != nil {
		result["firewall"] = ModuleConfig{Enabled: cloneBool(m.Firewall.Enabled)}
	}
	if m.Logging != nil {
		result["logging"] = ModuleConfig{Enabled: cloneBool(m.Logging.Enabled)}
	}
	if m.TailnetRouter != nil {
		result["tailnet-router"] = ModuleConfig{Enabled: cloneBool(m.TailnetRouter.Enabled)}
	}
	if m.Bifrost != nil {
		result["bifrost"] = ModuleConfig{Enabled: cloneBool(m.Bifrost.Enabled), Network: m.Bifrost.Network, Upstreams: cloneBifrostUpstreams(m.Bifrost.Upstreams), Models: cloneBifrostModels(m.Bifrost.Models)}
	}
	if m.Printer != nil {
		result["printer"] = ModuleConfig{Enabled: cloneBool(m.Printer.Enabled), Network: m.Printer.Network}
	}
	if m.AIOps != nil {
		result["aiops"] = ModuleConfig{Enabled: cloneBool(m.AIOps.Enabled), Network: m.AIOps.Network, ModelAlias: m.AIOps.ModelAlias}
	}
	if m.Gatus != nil {
		result["gatus"] = ModuleConfig{Enabled: cloneBool(m.Gatus.Enabled), Network: m.Gatus.Network}
	}
	if m.AirVPN != nil {
		result["airvpn"] = ModuleConfig{Enabled: cloneBool(m.AirVPN.Enabled), Servers: m.AirVPN.Servers}
	}
	if m.Arr != nil {
		network := m.Arr.Network
		if network == "" && m.Arr.Enabled != nil && *m.Arr.Enabled {
			network = ModuleNetworkAirVPN
		}
		result["arr"] = ModuleConfig{Enabled: cloneBool(m.Arr.Enabled), Network: network}
	}
	return result
}

func ModulesConfigFromMap(input map[string]ModuleConfig) ModulesConfig {
	var result ModulesConfig
	if _, ok := input["dns"]; ok {
		result.DNS = &DNSModuleConfig{}
	}
	if config, ok := input["monitoring"]; ok {
		result.Monitoring = &ToggleModuleConfig{Enabled: cloneBool(config.Enabled)}
	}
	if config, ok := input["firewall"]; ok {
		result.Firewall = &ToggleModuleConfig{Enabled: cloneBool(config.Enabled)}
	}
	if config, ok := input["logging"]; ok {
		result.Logging = &ToggleModuleConfig{Enabled: cloneBool(config.Enabled)}
	}
	if config, ok := input["tailnet-router"]; ok {
		result.TailnetRouter = &ToggleModuleConfig{Enabled: cloneBool(config.Enabled)}
	}
	if config, ok := input["bifrost"]; ok {
		result.Bifrost = &BifrostModuleConfig{Enabled: cloneBool(config.Enabled), Network: config.Network, Upstreams: cloneBifrostUpstreams(config.Upstreams), Models: cloneBifrostModels(config.Models)}
	}
	if config, ok := input["printer"]; ok {
		result.Printer = &NetworkToggleModuleConfig{Enabled: cloneBool(config.Enabled), Network: config.Network}
	}
	if config, ok := input["aiops"]; ok {
		result.AIOps = &AIOpsModuleConfig{Enabled: cloneBool(config.Enabled), Network: config.Network, ModelAlias: config.ModelAlias}
	}
	if config, ok := input["gatus"]; ok {
		result.Gatus = &NetworkToggleModuleConfig{Enabled: cloneBool(config.Enabled), Network: config.Network}
	}
	if config, ok := input["airvpn"]; ok {
		result.AirVPN = &AirVPNModuleConfig{Enabled: cloneBool(config.Enabled), Servers: config.Servers}
	}
	if config, ok := input["arr"]; ok {
		result.Arr = &ArrModuleConfig{Enabled: cloneBool(config.Enabled), Network: config.Network}
	}
	return result
}

func (m *ModulesConfig) Set(name string, config ModuleConfig) error {
	switch name {
	case "dns":
		if config.Enabled != nil {
			return errors.New("modules.dns.enabled: mandatory module cannot be disabled")
		}
		m.DNS = &DNSModuleConfig{}
	case "monitoring":
		if config.Network != "" {
			return errors.New("modules.monitoring.network: module is not network-capable")
		}
		m.Monitoring = &ToggleModuleConfig{Enabled: cloneBool(config.Enabled)}
	case "firewall":
		if config.Network != "" {
			return errors.New("modules.firewall.network: module is not network-capable")
		}
		m.Firewall = &ToggleModuleConfig{Enabled: cloneBool(config.Enabled)}
	case "logging":
		m.Logging = &ToggleModuleConfig{Enabled: cloneBool(config.Enabled)}
	case "tailnet-router":
		if config.Network != "" {
			return errors.New("modules.tailnet-router.network: module is not network-capable")
		}
		m.TailnetRouter = &ToggleModuleConfig{Enabled: cloneBool(config.Enabled)}
	case "bifrost":
		upstreams := config.Upstreams
		models := config.Models
		if len(upstreams) == 0 && len(models) == 0 && m.Bifrost != nil {
			upstreams = m.Bifrost.Upstreams
			models = m.Bifrost.Models
		}
		m.Bifrost = &BifrostModuleConfig{Enabled: cloneBool(config.Enabled), Network: config.Network, Upstreams: cloneBifrostUpstreams(upstreams), Models: cloneBifrostModels(models)}
	case "printer":
		m.Printer = &NetworkToggleModuleConfig{Enabled: cloneBool(config.Enabled), Network: config.Network}
	case "aiops":
		alias := config.ModelAlias
		if alias == "" && m.AIOps != nil {
			alias = m.AIOps.ModelAlias
		}
		m.AIOps = &AIOpsModuleConfig{Enabled: cloneBool(config.Enabled), Network: config.Network, ModelAlias: alias}
	case "gatus":
		m.Gatus = &NetworkToggleModuleConfig{Enabled: cloneBool(config.Enabled), Network: config.Network}
	case "airvpn":
		servers := config.Servers
		if servers == "" && m.AirVPN != nil {
			servers = m.AirVPN.Servers
		}
		m.AirVPN = &AirVPNModuleConfig{Enabled: cloneBool(config.Enabled), Servers: servers}
	case "arr":
		network := config.Network
		if network == "" && m.Arr != nil {
			network = m.Arr.Network
		}
		if network == "" && config.Enabled != nil && *config.Enabled {
			network = ModuleNetworkAirVPN
		}
		m.Arr = &ArrModuleConfig{Enabled: cloneBool(config.Enabled), Network: network}
	default:
		return fmt.Errorf("modules.%s: unknown first-party module", name)
	}
	return nil
}

func cloneCompanionConfig(value *CompanionConfig) *CompanionConfig {
	if value == nil {
		return nil
	}
	result := &CompanionConfig{Enabled: cloneBool(value.Enabled)}
	if value.Display != nil {
		result.Display = &CompanionCapabilityConfig{Enabled: cloneBool(value.Display.Enabled)}
	}
	if value.StreamDeck != nil {
		result.StreamDeck = &CompanionCapabilityConfig{Enabled: cloneBool(value.StreamDeck.Enabled)}
	}
	if value.PulseAgent != nil {
		result.PulseAgent = &CompanionCapabilityConfig{Enabled: cloneBool(value.PulseAgent.Enabled)}
	}
	return result
}

func cloneBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func boolPointer(value bool) *bool {
	return &value
}

func cloneBifrostUpstreams(values []BifrostUpstreamConfig) []BifrostUpstreamConfig {
	return append([]BifrostUpstreamConfig(nil), values...)
}

func cloneBifrostModels(values []BifrostModelConfig) []BifrostModelConfig {
	return append([]BifrostModelConfig(nil), values...)
}

func ValidateBifrostConfig(config ModuleConfig) error {
	if len(config.Upstreams) == 0 {
		return errors.New("modules.bifrost.upstreams must contain at least one upstream")
	}
	if len(config.Upstreams) > 16 {
		return errors.New("modules.bifrost.upstreams must contain at most 16 upstreams")
	}
	if len(config.Models) == 0 {
		return errors.New("modules.bifrost.models must contain at least one explicit model alias")
	}
	if len(config.Models) > 32 {
		return errors.New("modules.bifrost.models must contain at most 32 model aliases")
	}
	upstreams := make(map[string]struct{}, len(config.Upstreams))
	secretReferences := make(map[string]string, len(config.Upstreams))
	for _, upstream := range config.Upstreams {
		if !modelTokenPattern.MatchString(upstream.Name) {
			return fmt.Errorf("modules.bifrost.upstreams.name %q is not a safe token", upstream.Name)
		}
		if _, exists := upstreams[upstream.Name]; exists {
			return fmt.Errorf("modules.bifrost has duplicate upstream %q", upstream.Name)
		}
		upstreams[upstream.Name] = struct{}{}
		parsed, err := url.Parse(upstream.BaseURL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return fmt.Errorf("modules.bifrost upstream %s requires a valid HTTPS base_url", upstream.Name)
		}
		if !bifrostSecretReferencePattern.MatchString(upstream.APIKeySecret) {
			return fmt.Errorf("modules.bifrost upstream %s has an invalid api_key_secret reference", upstream.Name)
		}
		secretID := BifrostSecretReferenceID(upstream.APIKeySecret)
		if previous, exists := secretReferences[secretID]; exists && previous != upstream.APIKeySecret {
			return fmt.Errorf("modules.bifrost upstreams %q and %q have colliding api_key_secret references", previous, upstream.APIKeySecret)
		}
		secretReferences[secretID] = upstream.APIKeySecret
	}
	aliases := make(map[string]struct{}, len(config.Models))
	for _, model := range config.Models {
		if !modelTokenPattern.MatchString(model.Alias) {
			return fmt.Errorf("modules.bifrost model alias %q is not a safe token", model.Alias)
		}
		if _, exists := aliases[model.Alias]; exists {
			return fmt.Errorf("modules.bifrost has duplicate model alias %q", model.Alias)
		}
		aliases[model.Alias] = struct{}{}
		if _, exists := upstreams[model.Upstream]; !exists {
			return fmt.Errorf("modules.bifrost model alias %s references unknown upstream %q", model.Alias, model.Upstream)
		}
		if !providerModelPattern.MatchString(model.Model) {
			return fmt.Errorf("modules.bifrost model %s has an invalid provider model identifier", model.Alias)
		}
	}
	return nil
}

// ResolveBifrostAlias is the provider-neutral client contract. Callers may
// use only an explicitly declared alias; provider model identifiers are
// internal mapping data and are never accepted as implicit public models.
func ResolveBifrostAlias(config ModuleConfig, alias string) (BifrostModelConfig, error) {
	if err := ValidateBifrostConfig(config); err != nil {
		return BifrostModelConfig{}, err
	}
	for _, model := range config.Models {
		if model.Alias == alias {
			return model, nil
		}
	}
	return BifrostModelConfig{}, fmt.Errorf("undeclared Bifrost model alias %q", alias)
}

func ConfigFromSite(s Site) SiteConfig {
	return SiteConfig{
		APIVersion: s.APIVersion, PlatformVersion: s.PlatformVersion,
		SchemaVersion: s.SchemaVersion, StorageProfile: s.StorageProfile,
		StorageDevice: s.StorageDevice, Gateway: Gateway{Mode: s.Gateway.Mode, Upstream: s.Gateway.Upstream, Publish: append([]GatewayPublication(nil), s.Gateway.Publish...)},
		BootstrapAddress: s.BootstrapAddress,
		SSHIdentityFile:  s.SSHIdentityFile, PhysicalNetwork: s.PhysicalNetwork,
		TestedVersions: s.TestedVersions, Network: s.Network, PKI: s.PKI,
		SecretMetadata: s.SecretMetadata, Ownership: s.Ownership,
		Modules: ModulesConfigFromMap(s.ModuleConfig), DHCPReservations: configuredDHCPReservations(s),
		Companion:         cloneCompanionConfig(s.Companion),
		USBExports:        append([]USBExportBinding(nil), s.USBExports...),
		DNSRecords:        append([]UserDNSRecord(nil), s.DNSRecords...),
		UserFirewallRules: append([]UserFirewallRule(nil), s.UserFirewallRules...),
	}
}

// configuredDHCPReservations excludes reservations generated by a first-party
// module declaration. SiteConfig is desired operator input; module declarations
// are derived when it is composed into the canonical Site.
func configuredDHCPReservations(s Site) []DHCPReservation {
	derived := make(map[DHCPReservation]struct{})
	for _, declaration := range s.Declarations {
		for _, reservation := range declaration.DHCPReservations {
			derived[reservation] = struct{}{}
		}
	}
	reservations := make([]DHCPReservation, 0, len(s.DHCPReservations))
	for _, reservation := range s.DHCPReservations {
		if _, generated := derived[reservation]; !generated {
			reservations = append(reservations, reservation)
		}
	}
	return reservations
}

func (c SiteConfig) BaseSite() Site {
	mode := c.Gateway.Mode
	if mode == "" {
		mode = GatewayModeManaged
	}
	s := NewSite(c.SecretMetadata.InstallationID, c.SecretMetadata.AgeRecipient, mode)
	if c.Gateway.Upstream.Mode != "" {
		s.Gateway.Upstream.Mode = c.Gateway.Upstream.Mode
	}
	if c.Gateway.Upstream.MAC != "" {
		s.Gateway.Upstream.MAC = c.Gateway.Upstream.MAC
	}
	if len(c.Gateway.Publish) > 0 {
		s.Gateway.Publish = append([]GatewayPublication(nil), c.Gateway.Publish...)
	}
	if c.APIVersion != "" {
		s.APIVersion = c.APIVersion
	}
	if c.PlatformVersion != "" {
		s.PlatformVersion = c.PlatformVersion
	}
	if c.SchemaVersion != 0 {
		s.SchemaVersion = c.SchemaVersion
	}
	if c.StorageProfile != "" {
		s.StorageProfile = c.StorageProfile
	}
	if c.StorageDevice != "" {
		s.StorageDevice = c.StorageDevice
	}
	if c.BootstrapAddress != "" {
		s.BootstrapAddress = c.BootstrapAddress
	}
	if c.SSHIdentityFile != "" {
		s.SSHIdentityFile = c.SSHIdentityFile
	}
	if c.PhysicalNetwork.Mode != "" {
		s.PhysicalNetwork = c.PhysicalNetwork
	}
	if c.TestedVersions.Gateway != "" {
		s.TestedVersions.Gateway = c.TestedVersions.Gateway
	}
	if c.TestedVersions.Pulse != "" {
		s.TestedVersions.Pulse = c.TestedVersions.Pulse
	}
	if c.Network.Domain != "" {
		s.Network.Domain = c.Network.Domain
	}
	if len(c.Network.Zones) > 0 {
		s.Network.Zones = append([]Zone(nil), c.Network.Zones...)
		for index := range s.Network.Zones {
			// Keep existing v3 site files without the semantic field readable;
			// the fixed v3 names make this inference unambiguous. New rendered
			// configuration always includes the explicit type.
			if s.Network.Zones[index].Type == "" {
				s.Network.Zones[index].Type = zoneTypeForName(s.Network.Zones[index].Name)
			}
		}
	}
	if c.PKI.RootCommonName != "" {
		s.PKI.RootCommonName = c.PKI.RootCommonName
	}
	if c.PKI.RootFingerprint != "" {
		s.PKI.RootFingerprint = c.PKI.RootFingerprint
	}
	if c.PKI.RootExpiry != "" {
		s.PKI.RootExpiry = c.PKI.RootExpiry
	}
	if c.PKI.IssuingCommonName != "" {
		s.PKI.IssuingCommonName = c.PKI.IssuingCommonName
	}
	if c.PKI.IssuingFingerprint != "" {
		s.PKI.IssuingFingerprint = c.PKI.IssuingFingerprint
	}
	if c.PKI.IssuingExpiry != "" {
		s.PKI.IssuingExpiry = c.PKI.IssuingExpiry
	}
	if c.SecretMetadata.InstallationID != "" {
		s.SecretMetadata.InstallationID = c.SecretMetadata.InstallationID
	}
	if c.SecretMetadata.AgeRecipient != "" {
		s.SecretMetadata.AgeRecipient = c.SecretMetadata.AgeRecipient
	}
	if c.Ownership.PlatformGuestIDMin != 0 {
		s.Ownership.PlatformGuestIDMin = c.Ownership.PlatformGuestIDMin
	}
	if c.Ownership.PlatformGuestIDMax != 0 {
		s.Ownership.PlatformGuestIDMax = c.Ownership.PlatformGuestIDMax
	}
	if c.Ownership.ModuleGuestIDMin != 0 {
		s.Ownership.ModuleGuestIDMin = c.Ownership.ModuleGuestIDMin
	}
	if c.Ownership.ModuleGuestIDMax != 0 {
		s.Ownership.ModuleGuestIDMax = c.Ownership.ModuleGuestIDMax
	}
	if c.Ownership.UserGuestIDMin != 0 {
		s.Ownership.UserGuestIDMin = c.Ownership.UserGuestIDMin
	}
	if c.Ownership.UserGuestIDMax != 0 {
		s.Ownership.UserGuestIDMax = c.Ownership.UserGuestIDMax
	}
	s.Ownership.UserWorkloadsManaged = c.Ownership.UserWorkloadsManaged
	s.DHCPReservations = append([]DHCPReservation(nil), c.DHCPReservations...)
	s.DNSRecords = append([]UserDNSRecord(nil), c.DNSRecords...)
	s.UserFirewallRules = append([]UserFirewallRule(nil), c.UserFirewallRules...)
	s.USBExports = append([]USBExportBinding(nil), c.USBExports...)
	s.Companion = cloneCompanionConfig(c.Companion)
	s.ModuleConfig = c.Modules.Map()
	return s
}

func (c SiteConfig) Validate() error {
	return c.BaseSite().Validate()
}

func cloneModuleConfig(input map[string]ModuleConfig) map[string]ModuleConfig {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]ModuleConfig, len(input))
	for name, config := range input {
		output[name] = ModuleConfig{Enabled: cloneBool(config.Enabled), Network: config.Network, Servers: config.Servers, ModelAlias: config.ModelAlias, Upstreams: cloneBifrostUpstreams(config.Upstreams), Models: cloneBifrostModels(config.Models)}
	}
	return output
}
