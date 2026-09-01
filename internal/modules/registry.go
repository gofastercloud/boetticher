package modules

import (
	"fmt"
	"sort"

	"github.com/gofastercloud/boetticher/internal/model"
)

type EnablementPolicy string

const (
	Mandatory  EnablementPolicy = "mandatory"
	DefaultOn  EnablementPolicy = "default-on"
	DefaultOff EnablementPolicy = "default-off"
)

type Capability string

const (
	CapabilityGateway       Capability = "gateway"
	CapabilityDNS           Capability = "dns"
	CapabilityNTP           Capability = "ntp"
	CapabilityMonitoring    Capability = "monitoring"
	CapabilityLogging       Capability = "logging"
	CapabilityTailnetAccess Capability = "tailnet-access"
	CapabilityAirVPNTransit Capability = "airvpn-transit"
	CapabilityAIAPI         Capability = "ai-api"
)

type PlacementRequirement struct {
	ZoneType model.ZoneType
}

type ModuleDefinition struct {
	Name              string
	Description       string
	Version           string
	Policy            EnablementPolicy
	DependsOn         []string
	Requires          []Capability
	Provides          []Capability
	GuestIDs          []int
	ReservedVMIDStart int
	ReservedVMIDEnd   int
	Placement         PlacementRequirement
	Guests            []model.Component
	USBRequirements   []model.USBRequirement
	Configuration     []model.ModuleConfigField
	StaticDeviceSlots int
	NetworkCapable    bool
}

type Registry struct {
	definitions    map[string]ModuleDefinition
	duplicateNames []string
}

func NewRegistry(definitions []ModuleDefinition) Registry {
	result := Registry{definitions: make(map[string]ModuleDefinition, len(definitions))}
	for _, definition := range definitions {
		if _, exists := result.definitions[definition.Name]; exists {
			result.duplicateNames = append(result.duplicateNames, definition.Name)
		}
		result.definitions[definition.Name] = definition
	}
	return result
}

func FirstPartyRegistry() Registry {
	return Registry{definitions: map[string]ModuleDefinition{
		"dns": {
			Name: "dns", Description: "Mandatory DNS and NTP platform capability", Version: "1.0.0", Policy: Mandatory,
			Configuration: nil,

			Requires: []Capability{CapabilityGateway}, Provides: []Capability{CapabilityDNS, CapabilityNTP}, GuestIDs: []int{model.DNS01VMID, model.DNS02VMID}, Placement: PlacementRequirement{ZoneType: model.ZoneTypeInfrastructure}, Guests: []model.Component{
				{Name: "lab-dns-01", VMID: model.DNS01VMID, Hostname: "lab-dns-01", Zone: "INFRA", Address: "10.10.10.10", Role: "DNS/NTP", DNSAliases: []string{"dns01", "dns"}, Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true},
				{Name: "lab-dns-02", VMID: model.DNS02VMID, Hostname: "lab-dns-02", Zone: "INFRA", Address: "10.10.10.11", Role: "DNS/NTP", DNSAliases: []string{"dns02"}, Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true},
			},
		},
		"monitoring": {
			Name: "monitoring", Description: "Pulse platform monitoring with Proxmox API data and tagged-host hardware telemetry", Version: "1.0.0", Policy: DefaultOn,
			Requires: []Capability{CapabilityDNS}, Provides: []Capability{CapabilityMonitoring}, GuestIDs: []int{model.MonitorVMID}, Placement: PlacementRequirement{ZoneType: model.ZoneTypeInfrastructure}, Guests: []model.Component{
				{Name: "lab-monitor-01", VMID: model.MonitorVMID, Hostname: "lab-monitor-01", Zone: "INFRA", Address: "10.10.10.20", Role: "Pulse monitoring", DNSAliases: []string{"monitor"}, URL: "https://monitor." + model.DefaultDomain, Monitoring: true, Backup: true, MTLS: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true},
			},
		},
		"firewall": {
			Name: "firewall", Description: "Managed Debian gateway, nftables, and Kea capability", Version: "1.0.0", Policy: DefaultOn,
			Provides: []Capability{CapabilityGateway}, GuestIDs: []int{model.ProxmoxVMID}, Placement: PlacementRequirement{ZoneType: model.ZoneTypeManagement}, Guests: []model.Component{
				{Name: "lab-fw-01", VMID: model.ProxmoxVMID, Hostname: "lab-fw-01", Address: "10.10.99.1", Role: "Debian firewall", Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true},
			},
		},
		"logging": {
			Name: "logging", Description: "Central systemd journal collection", Version: "1.0.0", Policy: Mandatory,
			DependsOn: []string{"dns"}, Requires: []Capability{CapabilityDNS}, Provides: []Capability{CapabilityLogging}, GuestIDs: []int{model.LoggingVMID}, Placement: PlacementRequirement{ZoneType: model.ZoneTypeInfrastructure}, Guests: []model.Component{
				{Name: "lab-log-01", VMID: model.LoggingVMID, Hostname: "lab-log-01", Zone: "INFRA", Address: "10.10.10.40", Role: "Central systemd journal", DNSAliases: []string{"logs"}, Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true},
			},
		},
		"tailnet-router": {
			Name: "tailnet-router", Description: "Tailscale subnet router for the TRANSIT security edge", Version: "1.0.0", Policy: DefaultOff,
			Requires: []Capability{CapabilityGateway, CapabilityDNS}, Provides: []Capability{CapabilityTailnetAccess}, GuestIDs: []int{200}, ReservedVMIDStart: 200, ReservedVMIDEnd: 209,
			StaticDeviceSlots: 1, Placement: PlacementRequirement{ZoneType: model.ZoneTypeTransit}, Guests: []model.Component{
				{Name: "lab-tailnet-01", VMID: 200, Hostname: "lab-tailnet-01", Address: "10.10.5.10", Role: "Tailnet subnet router", DNSAliases: []string{"tailnet-router", "tailnet"}, Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true},
			},
		},
		"airvpn": {
			Name: "airvpn", Description: "AirVPN WireGuard external egress transit node", Version: "1.0.0", Policy: DefaultOff,
			Requires: []Capability{CapabilityGateway, CapabilityDNS, CapabilityNTP}, Provides: []Capability{CapabilityAirVPNTransit}, GuestIDs: []int{model.AirVPNGuestVMID}, ReservedVMIDStart: 260, ReservedVMIDEnd: 269,
			Configuration: []model.ModuleConfigField{{Key: "servers", Type: model.ModuleConfigString, Prompt: "AirVPN server selector", Description: "AirVPN named server, country, or region selector used once to generate the retained WireGuard profile", Required: true}},
			Placement:     PlacementRequirement{ZoneType: model.ZoneTypeTransit}, Guests: []model.Component{
				{Name: "lab-airvpn-01", VMID: model.AirVPNGuestVMID, Hostname: "lab-airvpn-01", Address: model.AirVPNGuestAddress, Role: "AirVPN WireGuard transit", DNSAliases: []string{"airvpn"}, Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true},
			},
		},
		"bifrost": {
			Name: "bifrost", Description: "mTLS-protected Bifrost AI API router", Version: "1.0.0", Policy: DefaultOff, NetworkCapable: true,
			Configuration: []model.ModuleConfigField{
				{Key: "upstreams", Type: model.ModuleConfigObjectList, Prompt: "AI Router upstreams", Description: "HTTPS provider endpoints and their SOPS secret references", Required: true, MinItems: 1, MaxItems: 16, ItemFields: []model.ModuleConfigField{
					{Key: "name", Type: model.ModuleConfigString, Prompt: "Upstream name", Required: true},
					{Key: "base_url", Type: model.ModuleConfigString, Prompt: "HTTPS base URL", Required: true},
					{Key: "api_key_secret", Type: model.ModuleConfigString, Prompt: "SOPS secret name", Description: "Name of the existing SOPS-managed provider credential; the credential value is collected separately", Required: true, Sensitive: true},
				}},
				{Key: "models", Type: model.ModuleConfigObjectList, Prompt: "AI Router model aliases", Description: "Provider-neutral aliases exposed to dependent modules", Required: true, MinItems: 1, MaxItems: 32, ItemFields: []model.ModuleConfigField{
					{Key: "alias", Type: model.ModuleConfigString, Prompt: "Public alias", Required: true},
					{Key: "upstream", Type: model.ModuleConfigEnum, Prompt: "Upstream", Required: true, Resolver: "bifrost-upstream-name"},
					{Key: "model", Type: model.ModuleConfigString, Prompt: "Provider model identifier", Required: true},
				}},
			},
			Requires: []Capability{CapabilityDNS}, Provides: []Capability{CapabilityAIAPI}, GuestIDs: []int{210}, ReservedVMIDStart: 210, ReservedVMIDEnd: 219,
			Placement: PlacementRequirement{ZoneType: model.ZoneTypeServers}, Guests: []model.Component{
				{Name: "lab-bifrost-01", VMID: 210, Hostname: "lab-bifrost-01", Address: "10.10.20.60", Role: "Bifrost AI API router", DNSAliases: []string{"bifrost", "ai"}, URL: "https://bifrost." + model.DefaultDomain, Monitoring: true, Backup: true, MTLS: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true},
			},
		},
		"printer": {
			Name: "printer", Description: "OctoPrint management for one USB-connected Ender-3 V3 SE", Version: "1.0.0", Policy: DefaultOff, NetworkCapable: true,
			Requires: []Capability{CapabilityDNS}, GuestIDs: []int{model.PrinterVMID}, ReservedVMIDStart: 230, ReservedVMIDEnd: 239,
			Placement: PlacementRequirement{ZoneType: model.ZoneTypeServers}, Guests: []model.Component{
				{Name: "lab-printer-01", VMID: model.PrinterVMID, Hostname: "lab-printer-01", Address: "10.10.20.80", Role: "OctoPrint for Ender-3 V3 SE", DNSAliases: []string{"octoprint", "printer"}, URL: "https://octoprint." + model.DefaultDomain, Monitoring: true, Backup: true, MTLS: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true},
			},
			USBRequirements: []model.USBRequirement{{Name: "serial", Guest: "lab-printer-01", DeviceType: "serial", Access: "rw", Required: true, AllowedIdentities: []model.USBIdentity{{VendorID: "1a86", ProductID: "7523"}}}},
		},
		"streamdeck": {
			Name: "streamdeck", Description: "Read-only Proxmox host status display backed by Pulse", Version: "1.0.0", Policy: DefaultOff, NetworkCapable: true,
			DependsOn: []string{"monitoring"}, Requires: []Capability{CapabilityDNS, CapabilityMonitoring}, GuestIDs: []int{model.StreamDeckVMID}, ReservedVMIDStart: 220, ReservedVMIDEnd: 229,
			Placement: PlacementRequirement{ZoneType: model.ZoneTypeServers}, Guests: []model.Component{
				{Name: "lab-streamdeck-01", VMID: model.StreamDeckVMID, Hostname: "lab-streamdeck-01", Address: "10.10.20.70", Role: "Pulse Proxmox host status display", Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true},
			},
			USBRequirements: []model.USBRequirement{{Name: "display", Guest: "lab-streamdeck-01", DeviceType: "raw-usb", Access: "rw", Required: true, AllowedIdentities: []model.USBIdentity{{VendorID: "0fd9", ProductID: "006d"}}}},
		},
		"aiops": {
			Name: "aiops", Description: "Read-only HolmesGPT incident investigation", Version: "1.0.0", Policy: DefaultOff, NetworkCapable: true,
			Configuration: []model.ModuleConfigField{{Key: "model_alias", Type: model.ModuleConfigModelAlias, Prompt: "AI Router model alias", Description: "An alias explicitly declared by the Bifrost module", Required: true, Resolver: "bifrost-model-alias"}},
			DependsOn:     []string{"monitoring", "logging", "bifrost"}, Requires: []Capability{CapabilityMonitoring, CapabilityLogging, CapabilityAIAPI, CapabilityDNS, CapabilityNTP}, GuestIDs: []int{240}, ReservedVMIDStart: 240, ReservedVMIDEnd: 249,
			Placement: PlacementRequirement{ZoneType: model.ZoneTypeServers}, Guests: []model.Component{
				{Name: "lab-aiops-01", VMID: 240, Hostname: "lab-aiops-01", Zone: "SERVERS", Address: "10.10.20.90", Role: "HolmesGPT AIOps investigation", DNSAliases: []string{"aiops"}, URL: "https://aiops." + model.DefaultDomain, Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true},
			},
		},
		"gatus": {Name: "gatus", Description: "Generated status page for declared services", Version: "1.0.0", Policy: DefaultOff, NetworkCapable: true, DependsOn: []string{"monitoring"}, Requires: []Capability{CapabilityDNS}, GuestIDs: []int{model.GatusVMID}, ReservedVMIDStart: 250, ReservedVMIDEnd: 259, Placement: PlacementRequirement{ZoneType: model.ZoneTypeServers}, Guests: []model.Component{{Name: "lab-gatus-01", VMID: model.GatusVMID, Hostname: "lab-gatus-01", Address: "10.10.20.100", Role: "Gatus status page", DNSAliases: []string{"gatus"}, URL: "https://gatus." + model.DefaultDomain, Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true}}},
	}}
}

func (r Registry) Definitions() []ModuleDefinition {
	result := make([]ModuleDefinition, 0, len(r.definitions))
	for _, definition := range r.definitions {
		result = append(result, definition)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func (r Registry) Definition(name string) (ModuleDefinition, bool) {
	definition, ok := r.definitions[name]
	return definition, ok
}

// ConfigurationFields returns the operator schema for a module. Resolver
// results are derived from the same typed site configuration used by Compose;
// they are never an additional source of allowed values.
func (r Registry) ConfigurationFields(name string, config model.SiteConfig) ([]model.ModuleConfigField, error) {
	definition, ok := r.Definition(name)
	if !ok {
		return nil, fmt.Errorf("unknown first-party module %q", name)
	}
	fields := cloneConfigurationFields(definition.Configuration)
	if definition.NetworkCapable {
		fields = append([]model.ModuleConfigField{{Key: "network", Type: model.ModuleConfigEnum, Prompt: "Network egress mode", Description: "Route declared external application egress directly or through the AirVPN transit node", Default: string(model.ModuleNetworkDirect), AllowedValues: []string{string(model.ModuleNetworkDirect), string(model.ModuleNetworkAirVPN)}}}, fields...)
	}
	var resolve func([]model.ModuleConfigField)
	resolve = func(values []model.ModuleConfigField) {
		for index := range values {
			switch values[index].Resolver {
			case "bifrost-model-alias":
				for _, item := range config.Modules.Map()["bifrost"].Models {
					values[index].AllowedValues = append(values[index].AllowedValues, item.Alias)
				}
			case "bifrost-upstream-name":
				for _, item := range config.Modules.Map()["bifrost"].Upstreams {
					values[index].AllowedValues = append(values[index].AllowedValues, item.Name)
				}
			}
			resolve(values[index].ItemFields)
		}
	}
	resolve(fields)
	return fields, nil
}

func cloneConfigurationFields(values []model.ModuleConfigField) []model.ModuleConfigField {
	result := make([]model.ModuleConfigField, len(values))
	for index, value := range values {
		result[index] = value
		result[index].AllowedValues = append([]string(nil), value.AllowedValues...)
		result[index].ItemFields = cloneConfigurationFields(value.ItemFields)
	}
	return result
}

type ResolvedModule struct {
	Definition ModuleDefinition
	Enabled    bool
	Reason     string
	State      string
}

func (r Registry) Resolve(config model.SiteConfig) ([]ResolvedModule, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	resolved, err := r.resolve(config, config.Modules.Map())
	if err != nil {
		return nil, err
	}
	if err := r.validateUSBBindings(config, resolved); err != nil {
		return nil, err
	}
	return resolved, nil
}

func (r Registry) validateUSBBindings(config model.SiteConfig, resolved []ResolvedModule) error {
	type key struct{ module, requirement string }
	requirements := map[key]model.USBRequirement{}
	enabled := map[string]bool{}
	for _, definition := range r.Definitions() {
		for _, requirement := range definition.USBRequirements {
			requirements[key{definition.Name, requirement.Name}] = requirement
		}
	}
	for _, module := range resolved {
		enabled[module.Definition.Name] = module.Enabled
	}
	bound := map[key]bool{}
	ports, serialIdentities := map[string]bool{}, map[string]bool{}
	for _, binding := range config.USBExports {
		k := key{binding.Module, binding.Requirement}
		requirement, ok := requirements[k]
		if !ok {
			return fmt.Errorf("usb_exports binding %s/%s does not name a compiled-in module requirement", binding.Module, binding.Requirement)
		}
		allowed := false
		for _, identity := range requirement.AllowedIdentities {
			if identity.VendorID == binding.VendorID && identity.ProductID == binding.ProductID {
				allowed = true
			}
		}
		if !allowed {
			return fmt.Errorf("usb_exports identity %s:%s is not allowed for %s/%s", binding.VendorID, binding.ProductID, binding.Module, binding.Requirement)
		}
		if bound[k] {
			return fmt.Errorf("duplicate USB binding %s/%s", binding.Module, binding.Requirement)
		}
		if ports[binding.Port] {
			return fmt.Errorf("duplicate USB physical port %s", binding.Port)
		}
		if binding.Serial != "" {
			identity := binding.VendorID + ":" + binding.ProductID + ":" + binding.Serial
			if serialIdentities[identity] {
				return fmt.Errorf("duplicate USB physical identity %s", identity)
			}
			serialIdentities[identity] = true
		}
		bound[k], ports[binding.Port] = true, true
	}
	for k, requirement := range requirements {
		if enabled[k.module] && requirement.Required && !bound[k] {
			return fmt.Errorf("modules.%s requires usb_exports binding %s/%s", k.module, k.module, k.requirement)
		}
	}
	return nil
}

func (r Registry) Validate() error {
	if len(r.duplicateNames) > 0 {
		names := append([]string(nil), r.duplicateNames...)
		sort.Strings(names)
		return fmt.Errorf("duplicate module definition %q", names[0])
	}
	reserved := make(map[int]string)
	guestVMIDs := make(map[int]string)
	guestAddresses := make(map[string]string)
	for _, definition := range r.Definitions() {
		if definition.Name == "" || definition.Version == "" {
			return fmt.Errorf("module definition has incomplete identity")
		}
		if definition.ReservedVMIDStart != 0 || definition.ReservedVMIDEnd != 0 {
			if definition.ReservedVMIDStart < model.ModuleGuestIDMin || definition.ReservedVMIDEnd > model.ModuleGuestIDMax || definition.ReservedVMIDStart > definition.ReservedVMIDEnd {
				return fmt.Errorf("module %s has invalid reserved VMID block %d-%d", definition.Name, definition.ReservedVMIDStart, definition.ReservedVMIDEnd)
			}
			for vmid := definition.ReservedVMIDStart; vmid <= definition.ReservedVMIDEnd; vmid++ {
				if previous, exists := reserved[vmid]; exists && previous != definition.Name {
					return fmt.Errorf("reserved VMID %d collides between modules %s and %s", vmid, previous, definition.Name)
				}
				reserved[vmid] = definition.Name
			}
		}
		if definition.Placement.ZoneType != "" && !supportedPlacementZoneType(definition.Placement.ZoneType) {
			return fmt.Errorf("module %s has unknown placement zone type %q", definition.Name, definition.Placement.ZoneType)
		}
		if err := validateConfigurationFields(definition.Name, definition.Configuration); err != nil {
			return err
		}
		guestNames := make(map[string]bool, len(definition.Guests))
		for _, guest := range definition.Guests {
			guestNames[guest.Name] = true
		}
		for _, requirement := range definition.USBRequirements {
			if requirement.Name == "" || !guestNames[requirement.Guest] || requirement.Access != "rw" || len(requirement.AllowedIdentities) == 0 {
				return fmt.Errorf("module %s has invalid USB requirement %q", definition.Name, requirement.Name)
			}
			if requirement.DeviceType != "raw-usb" && requirement.DeviceType != "serial" {
				return fmt.Errorf("module %s USB device type %q is unsupported", definition.Name, requirement.DeviceType)
			}
		}
		for _, guest := range definition.Guests {
			if previous, exists := guestVMIDs[guest.VMID]; exists && guest.VMID != 0 && previous != definition.Name {
				return fmt.Errorf("guest VMID %d collides between modules %s and %s", guest.VMID, previous, definition.Name)
			}
			if guest.VMID != 0 {
				guestVMIDs[guest.VMID] = definition.Name
			}
			if previous, exists := guestAddresses[guest.Address]; exists && guest.Address != "" && previous != definition.Name {
				return fmt.Errorf("guest address %s collides between modules %s and %s", guest.Address, previous, definition.Name)
			}
			if guest.Address != "" {
				guestAddresses[guest.Address] = definition.Name
			}
			if definition.ReservedVMIDStart != 0 && (guest.VMID < definition.ReservedVMIDStart || guest.VMID > definition.ReservedVMIDEnd) {
				return fmt.Errorf("module %s guest VMID %d is outside its reserved block", definition.Name, guest.VMID)
			}
			if guest.VMID != 0 && !containsInt(definition.GuestIDs, guest.VMID) {
				return fmt.Errorf("module %s guest VMID %d is not declared in GuestIDs", definition.Name, guest.VMID)
			}
		}
	}
	for vmid, owner := range reserved {
		if guestOwner, exists := guestVMIDs[vmid]; exists && guestOwner != owner {
			return fmt.Errorf("reserved VMID %d for module %s collides with guest owned by %s", vmid, owner, guestOwner)
		}
	}
	return nil
}

func validateConfigurationFields(module string, fields []model.ModuleConfigField) error {
	seen := make(map[string]bool, len(fields))
	for _, field := range fields {
		if field.Key == "" || !modelConfigurationToken(field.Key) || seen[field.Key] {
			return fmt.Errorf("module %s has invalid or duplicate configuration field %q", module, field.Key)
		}
		seen[field.Key] = true
		if field.Prompt == "" {
			return fmt.Errorf("module %s configuration field %s has no prompt", module, field.Key)
		}
		switch field.Type {
		case model.ModuleConfigBool, model.ModuleConfigString, model.ModuleConfigEnum, model.ModuleConfigModelAlias, model.ModuleConfigObjectList:
		default:
			return fmt.Errorf("module %s configuration field %s has unsupported type %q", module, field.Key, field.Type)
		}
		if field.Resolver != "" {
			if field.Type != model.ModuleConfigEnum && field.Type != model.ModuleConfigModelAlias {
				return fmt.Errorf("module %s configuration field %s has a resolver for a non-choice type", module, field.Key)
			}
			switch field.Resolver {
			case "bifrost-model-alias", "bifrost-upstream-name":
			default:
				return fmt.Errorf("module %s configuration field %s has unknown resolver %q", module, field.Key, field.Resolver)
			}
		}
		if field.Type == model.ModuleConfigEnum && len(field.AllowedValues) == 0 && field.Resolver == "" {
			return fmt.Errorf("module %s configuration field %s enum has no allowed values", module, field.Key)
		}
		if field.Type == model.ModuleConfigObjectList {
			if field.MinItems < 0 || field.MaxItems < field.MinItems || field.MaxItems == 0 || len(field.ItemFields) == 0 {
				return fmt.Errorf("module %s configuration field %s has invalid object-list bounds", module, field.Key)
			}
			if err := validateConfigurationFields(module+"."+field.Key, field.ItemFields); err != nil {
				return err
			}
		}
		if field.Default != "" && field.Type == model.ModuleConfigEnum && !containsString(field.AllowedValues, field.Default) {
			return fmt.Errorf("module %s configuration field %s default is not allowed", module, field.Key)
		}
	}
	return nil
}

func modelConfigurationToken(value string) bool {
	if len(value) > 64 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' || character == '-') {
			return false
		}
	}
	return true
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func supportedPlacementZoneType(value model.ZoneType) bool {
	switch value {
	case model.ZoneTypeInfrastructure, model.ZoneTypeTrusted, model.ZoneTypeServers, model.ZoneTypeSandbox, model.ZoneTypeManagement, model.ZoneTypeTransit:
		return true
	default:
		return false
	}
}

func containsInt(values []int, wanted int) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// resolve accepts a resolved lookup projection for synthetic registry tests
// and internal registry composition. Persisted SiteConfig uses ModulesConfig,
// which remains deliberately typed and strict.
func (r Registry) resolve(config model.SiteConfig, configs map[string]model.ModuleConfig) ([]ResolvedModule, error) {
	if err := validateModuleConfigNames(r, configs); err != nil {
		return nil, err
	}
	if err := validateModuleNetworkModes(r, configs); err != nil {
		return nil, err
	}
	if airvpn, ok := configs["airvpn"]; ok && (airvpn.Enabled != nil && *airvpn.Enabled || airvpn.Servers != "") {
		if airvpn.Servers == "" {
			return nil, fmt.Errorf("modules.airvpn.servers: a server or region selector is required when AirVPN is enabled")
		}
		if !modelToken(airvpn.Servers) {
			return nil, fmt.Errorf("modules.airvpn.servers: selector contains unsafe characters")
		}
	}
	for name, moduleConfig := range configs {
		if name == "bifrost" && (moduleConfig.Enabled != nil && *moduleConfig.Enabled || len(moduleConfig.Upstreams) > 0 || len(moduleConfig.Models) > 0) {
			if err := model.ValidateBifrostConfig(moduleConfig); err != nil {
				return nil, err
			}
		}
		if name == "aiops" && moduleConfig.Enabled != nil && *moduleConfig.Enabled {
			if !modelToken(moduleConfig.ModelAlias) {
				return nil, fmt.Errorf("modules.aiops.model_alias: a safe declared AI Router alias is required")
			}
			bifrost, ok := configs["bifrost"]
			if !ok {
				return nil, fmt.Errorf("modules.aiops.model_alias: Bifrost configuration is required")
			}
			if _, err := model.ResolveBifrostAlias(bifrost, moduleConfig.ModelAlias); err != nil {
				return nil, fmt.Errorf("modules.aiops.model_alias: %w", err)
			}
		}
	}
	active := map[string]bool{}
	reasons := map[string]string{}
	for _, definition := range r.Definitions() {
		requested, exists := configs[definition.Name]
		enabled := defaultEnabled(definition.Policy)
		reason := "default"
		if definition.Policy == Mandatory {
			if exists && requested.Enabled != nil && !*requested.Enabled {
				return nil, fmt.Errorf("modules.%s.enabled: %s is mandatory and cannot be disabled", definition.Name, definition.Name)
			}
			enabled, reason = true, "mandatory"
		} else if exists && requested.Enabled != nil {
			enabled = *requested.Enabled
			reason = "explicit"
		}
		if enabled {
			active[definition.Name] = true
			reasons[definition.Name] = reason
		}
	}
	if config.Gateway.Mode == model.GatewayModeExternal {
		if _, hasFirewall := r.definitions["firewall"]; hasFirewall {
			firewallConfig, exists := configs["firewall"]
			if !exists || firewallConfig.Enabled == nil || *firewallConfig.Enabled {
				return nil, fmt.Errorf("modules.firewall.enabled: external gateway mode requires the managed firewall module to be explicitly disabled")
			}
		}
		active["firewall"] = false
	}
	for name, moduleConfig := range configs {
		if moduleConfig.Network != model.ModuleNetworkAirVPN || !active[name] {
			continue
		}
		airvpn, explicitlyConfigured := configs["airvpn"]
		if !explicitlyConfigured || airvpn.Enabled == nil || !*airvpn.Enabled || !active["airvpn"] {
			return nil, fmt.Errorf("modules.%s.network: AirVPN egress requires modules.airvpn.enabled=true", name)
		}
	}
	for name := range active {
		if !active[name] {
			continue
		}
		definition := r.definitions[name]
		for _, dependency := range definition.DependsOn {
			if _, ok := r.definitions[dependency]; !ok {
				return nil, fmt.Errorf("modules.%s: dependency %q is not registered", name, dependency)
			}
			if requested, exists := configs[dependency]; exists && requested.Enabled != nil && !*requested.Enabled {
				return nil, fmt.Errorf("modules.%s: required dependency %q is explicitly disabled", name, dependency)
			}
			if !active[dependency] {
				active[dependency] = true
				reasons[dependency] = "dependency"
			}
		}
	}
	// Repeat until dependencies of newly activated dependencies are included.
	changed := true
	for changed {
		changed = false
		for name, enabled := range active {
			if !enabled {
				continue
			}
			for _, dependency := range r.definitions[name].DependsOn {
				if !active[dependency] {
					active[dependency] = true
					reasons[dependency] = "dependency"
					changed = true
				}
			}
		}
	}
	capabilityProviders := map[Capability]string{}
	if config.Gateway.Mode == model.GatewayModeExternal {
		capabilityProviders[CapabilityGateway] = "external gateway"
	}
	for _, definition := range r.Definitions() {
		if !active[definition.Name] {
			continue
		}
		for _, capability := range definition.Provides {
			if existing, ok := capabilityProviders[capability]; ok && existing != definition.Name {
				return nil, fmt.Errorf("capability %s has incompatible providers %q and %q", capability, existing, definition.Name)
			}
			capabilityProviders[capability] = definition.Name
		}
	}
	for _, definition := range r.Definitions() {
		if !active[definition.Name] {
			continue
		}
		for _, capability := range definition.Requires {
			if _, ok := capabilityProviders[capability]; !ok {
				return nil, fmt.Errorf("modules.%s: required capability %s is unavailable", definition.Name, capability)
			}
		}
	}
	ordered, err := topologicalOrder(r, active, configs)
	if err != nil {
		return nil, err
	}
	result := make([]ResolvedModule, 0, len(ordered))
	for _, name := range ordered {
		definition := r.definitions[name]
		result = append(result, ResolvedModule{Definition: definition, Enabled: true, Reason: reasons[name], State: "Enabled"})
	}
	for _, definition := range r.Definitions() {
		if active[definition.Name] {
			continue
		}
		reason := "default"
		if requested, exists := configs[definition.Name]; exists && requested.Enabled != nil {
			reason = "explicit"
		}
		result = append(result, ResolvedModule{Definition: definition, Enabled: false, Reason: reason, State: "Disabled"})
	}
	return result, nil
}

func validateModuleConfigNames(r Registry, configs map[string]model.ModuleConfig) error {
	for name := range configs {
		if _, ok := r.definitions[name]; !ok {
			return fmt.Errorf("modules.%s: unknown first-party module", name)
		}
	}
	return nil
}

func validateModuleNetworkModes(r Registry, configs map[string]model.ModuleConfig) error {
	for name, config := range configs {
		if config.Network == "" || config.Network == model.ModuleNetworkDirect {
			continue
		}
		if config.Network != model.ModuleNetworkAirVPN {
			return fmt.Errorf("modules.%s.network: unsupported mode %q", name, config.Network)
		}
		definition, ok := r.Definition(name)
		if !ok {
			continue
		}
		if !definition.NetworkCapable {
			return fmt.Errorf("modules.%s.network: module is not network-capable", name)
		}
	}
	return nil
}

func modelToken(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

func defaultEnabled(policy EnablementPolicy) bool {
	return policy == Mandatory || policy == DefaultOn
}

func topologicalOrder(r Registry, active map[string]bool, configs map[string]model.ModuleConfig) ([]string, error) {
	state := map[string]int{}
	result := []string{}
	var visit func(string) error
	visit = func(name string) error {
		if state[name] == 1 {
			return fmt.Errorf("module dependency cycle includes %q", name)
		}
		if state[name] == 2 {
			return nil
		}
		state[name] = 1
		definition := r.definitions[name]
		dependencies := effectiveDependencies(r, definition, active, configs)
		sort.Strings(dependencies)
		for _, dependency := range dependencies {
			if !active[dependency] {
				return fmt.Errorf("module %s depends on disabled module %s", name, dependency)
			}
			if _, ok := r.definitions[dependency]; !ok {
				return fmt.Errorf("module %s depends on unknown module %s", name, dependency)
			}
			if err := visit(dependency); err != nil {
				return err
			}
		}
		state[name] = 2
		result = append(result, name)
		return nil
	}
	names := make([]string, 0, len(active))
	for name, enabled := range active {
		if enabled {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		if err := visit(name); err != nil {
			return nil, err
		}
	}
	return result, nil
}

// effectiveDependencies includes both concrete module dependencies and the
// active first-party provider of each required capability. External providers
// are deliberately absent from this graph.
func effectiveDependencies(r Registry, definition ModuleDefinition, active map[string]bool, configs map[string]model.ModuleConfig) []string {
	seen := map[string]bool{}
	dependencies := append([]string(nil), definition.DependsOn...)
	if definition.NetworkCapable && configs[definition.Name].Network == model.ModuleNetworkAirVPN {
		dependencies = append(dependencies, "airvpn")
	}
	for _, dependency := range dependencies {
		seen[dependency] = true
	}
	for _, capability := range definition.Requires {
		for _, candidate := range r.Definitions() {
			if !active[candidate.Name] || candidate.Name == definition.Name {
				continue
			}
			for _, provided := range candidate.Provides {
				if provided == capability && !seen[candidate.Name] {
					dependencies = append(dependencies, candidate.Name)
					seen[candidate.Name] = true
				}
			}
		}
	}
	return dependencies
}
