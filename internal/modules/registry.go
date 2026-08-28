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
}

type Registry struct {
	definitions map[string]ModuleDefinition
}

func NewRegistry(definitions []ModuleDefinition) Registry {
	result := Registry{definitions: make(map[string]ModuleDefinition, len(definitions))}
	for _, definition := range definitions {
		result.definitions[definition.Name] = definition
	}
	return result
}

func FirstPartyRegistry() Registry {
	return Registry{definitions: map[string]ModuleDefinition{
		"dns": {
			Name: "dns", Description: "Mandatory DNS and NTP platform capability", Version: "1.0.0", Policy: Mandatory,

			Requires: []Capability{CapabilityGateway}, Provides: []Capability{CapabilityDNS, CapabilityNTP}, GuestIDs: []int{model.DNS01VMID, model.DNS02VMID}, Placement: PlacementRequirement{ZoneType: model.ZoneTypeInfrastructure}, Guests: []model.Component{
				{Name: "lab-dns-01", VMID: model.DNS01VMID, Hostname: "lab-dns-01", Zone: "INFRA", Address: "10.10.10.10", Role: "DNS/NTP", DNSAliases: []string{"dns01", "dns"}, Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true},
				{Name: "lab-dns-02", VMID: model.DNS02VMID, Hostname: "lab-dns-02", Zone: "INFRA", Address: "10.10.10.11", Role: "DNS/NTP", DNSAliases: []string{"dns02"}, Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true},
			},
		},
		"monitoring": {
			Name: "monitoring", Description: "Pulse platform monitoring with Proxmox API data and tagged-host hardware telemetry", Version: "1.0.0", Policy: DefaultOn,
			Requires: []Capability{CapabilityDNS}, Provides: []Capability{CapabilityMonitoring}, GuestIDs: []int{model.MonitorVMID}, Placement: PlacementRequirement{ZoneType: model.ZoneTypeInfrastructure}, Guests: []model.Component{
				{Name: "lab-monitor-01", VMID: model.MonitorVMID, Hostname: "lab-monitor-01", Zone: "INFRA", Address: "10.10.10.20", Role: "Pulse monitoring", DNSAliases: []string{"monitor"}, URL: "https://monitor." + model.DefaultDomain, Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true},
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
			Placement: PlacementRequirement{ZoneType: model.ZoneTypeTransit}, Guests: []model.Component{
				{Name: "lab-tailnet-01", VMID: 200, Hostname: "lab-tailnet-01", Address: "10.10.5.10", Role: "Tailnet subnet router", DNSAliases: []string{"tailnet-router", "tailnet"}, Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true},
			},
		},
		"litellm": {
			Name: "litellm", Description: "mTLS-protected LiteLLM AI API router", Version: "1.0.0", Policy: DefaultOff,
			Requires: []Capability{CapabilityDNS}, Provides: []Capability{CapabilityAIAPI}, GuestIDs: []int{210}, ReservedVMIDStart: 210, ReservedVMIDEnd: 219,
			Placement: PlacementRequirement{ZoneType: model.ZoneTypeServers}, Guests: []model.Component{
				{Name: "lab-litellm-01", VMID: 210, Hostname: "lab-litellm-01", Address: "10.10.20.60", Role: "LiteLLM AI API router", DNSAliases: []string{"litellm", "ai"}, URL: "https://litellm." + model.DefaultDomain, Monitoring: true, Backup: true, MTLS: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true},
			},
		},
		"aiops": {
			Name: "aiops", Description: "Read-only HolmesGPT incident investigation", Version: "1.0.0", Policy: DefaultOff,
			DependsOn: []string{"monitoring", "logging", "litellm"}, Requires: []Capability{CapabilityMonitoring, CapabilityLogging, CapabilityAIAPI, CapabilityDNS, CapabilityNTP}, GuestIDs: []int{240}, ReservedVMIDStart: 240, ReservedVMIDEnd: 249,
			Placement: PlacementRequirement{ZoneType: model.ZoneTypeServers}, Guests: []model.Component{
				{Name: "lab-aiops-01", VMID: 240, Hostname: "lab-aiops-01", Zone: "SERVERS", Address: "10.10.20.90", Role: "HolmesGPT AIOps investigation", DNSAliases: []string{"aiops"}, URL: "https://aiops." + model.DefaultDomain, Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true},
			},
		},
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
	return r.resolve(config, config.Modules.Map())
}

func (r Registry) Validate() error {
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
	for name, moduleConfig := range configs {
		if moduleConfig.Provider != "" && name != "dns" {
			return nil, fmt.Errorf("modules.%s.provider: provider selection is only supported by dns", name)
		}
		if name == "litellm" && (moduleConfig.Enabled != nil && *moduleConfig.Enabled || len(moduleConfig.Upstreams) > 0 || len(moduleConfig.Models) > 0) {
			if err := model.ValidateLiteLLMConfig(moduleConfig); err != nil {
				return nil, err
			}
		}
		if name == "aiops" && moduleConfig.Enabled != nil && *moduleConfig.Enabled {
			if !modelToken(moduleConfig.ModelAlias) {
				return nil, fmt.Errorf("modules.aiops.model_alias: a safe declared AI Router alias is required")
			}
			litellm, ok := configs["litellm"]
			if !ok {
				return nil, fmt.Errorf("modules.aiops.model_alias: LiteLLM configuration is required")
			}
			if _, err := model.ResolveLiteLLMAlias(litellm, moduleConfig.ModelAlias); err != nil {
				return nil, fmt.Errorf("modules.aiops.model_alias: %w", err)
			}
		}
		if name == "dns" && moduleConfig.Provider != "" && moduleConfig.Provider != string(model.DNSProviderBlocky) && moduleConfig.Provider != string(model.DNSProviderAdGuard) {
			return nil, fmt.Errorf("modules.dns.provider: expected one of: blocky, adguard")
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
	ordered, err := topologicalOrder(r, active)
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

func validateModuleConfigNames(r Registry, configs map[string]model.ModuleConfig) error {
	for name := range configs {
		if _, ok := r.definitions[name]; !ok {
			return fmt.Errorf("modules.%s: unknown first-party module", name)
		}
	}
	return nil
}

func defaultEnabled(policy EnablementPolicy) bool {
	return policy == Mandatory || policy == DefaultOn
}

func topologicalOrder(r Registry, active map[string]bool) ([]string, error) {
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
		dependencies := effectiveDependencies(r, definition, active)
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
func effectiveDependencies(r Registry, definition ModuleDefinition, active map[string]bool) []string {
	seen := map[string]bool{}
	dependencies := append([]string(nil), definition.DependsOn...)
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
