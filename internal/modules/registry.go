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
	CapabilityGateway    Capability = "gateway"
	CapabilityDNS        Capability = "dns"
	CapabilityNTP        Capability = "ntp"
	CapabilityMonitoring Capability = "monitoring"
	CapabilityLogging    Capability = "logging"
)

type ModuleDefinition struct {
	Name        string
	Description string
	Version     string
	Policy      EnablementPolicy
	DependsOn   []string
	Requires    []Capability
	Provides    []Capability
	GuestIDs    []int
	Components  []model.Component
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
			Requires: []Capability{CapabilityGateway}, Provides: []Capability{CapabilityDNS, CapabilityNTP}, GuestIDs: []int{model.DNS01VMID, model.DNS02VMID}, Components: []model.Component{
				{Name: "lab-dns-01", VMID: model.DNS01VMID, Hostname: "lab-dns-01", Zone: "SERVERS", Address: "10.10.20.10", Role: "DNS/NTP", DNSAliases: []string{"dns01", "dns"}, Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true},
				{Name: "lab-dns-02", VMID: model.DNS02VMID, Hostname: "lab-dns-02", Zone: "SERVERS", Address: "10.10.20.11", Role: "DNS/NTP", DNSAliases: []string{"dns02"}, Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true},
			},
		},
		"monitoring": {
			Name: "monitoring", Description: "Zabbix platform monitoring capability", Version: "1.0.0", Policy: DefaultOn,
			Requires: []Capability{CapabilityDNS}, Provides: []Capability{CapabilityMonitoring}, GuestIDs: []int{model.MonitorVMID}, Components: []model.Component{
				{Name: "lab-monitor-01", VMID: model.MonitorVMID, Hostname: "lab-monitor-01", Zone: "SERVERS", Address: "10.10.20.20", Role: "Zabbix", DNSAliases: []string{"monitor"}, URL: "https://monitor." + model.DefaultDomain, Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true},
			},
		},
		"firewall": {
			Name: "firewall", Description: "Managed Debian gateway, nftables, and Kea capability", Version: "1.0.0", Policy: DefaultOn,
			Provides: []Capability{CapabilityGateway}, GuestIDs: []int{model.ProxmoxVMID}, Components: []model.Component{
				{Name: "lab-fw-01", VMID: model.ProxmoxVMID, Hostname: "lab-fw-01", Zone: "MGMT", Address: "10.10.99.1", Role: "Debian firewall", Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true},
			},
		},
		"logging": {
			Name: "logging", Description: "Central systemd journal collection", Version: "1.0.0", Policy: Mandatory,
			DependsOn: []string{"dns"}, Requires: []Capability{CapabilityDNS}, Provides: []Capability{CapabilityLogging}, GuestIDs: []int{model.LoggingVMID}, Components: []model.Component{
				{Name: "lab-log-01", VMID: model.LoggingVMID, Hostname: "lab-log-01", Zone: "SERVERS", Address: "10.10.20.40", Role: "Central systemd journal", DNSAliases: []string{"logs"}, Monitoring: true, Backup: true, SSHManaged: true, JumpAllowed: true, ProductOwned: true},
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
	return r.resolve(config, config.Modules.Map())
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
	if dnsConfig, exists := configs["dns"]; exists && dnsConfig.Enabled != nil && !*dnsConfig.Enabled {
		return nil, fmt.Errorf("modules.dns.enabled: dns is mandatory and cannot be disabled")
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
		result = append(result, ResolvedModule{Definition: definition, Enabled: true, Reason: reasons[name], State: "Ready"})
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
