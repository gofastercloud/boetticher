package modules

import (
	"fmt"
	"net/url"
	"sort"

	"github.com/gofastercloud/boetticher/internal/model"
)

// Compose resolves SiteConfig into the canonical Site consumed by core
// providers. The resulting component list is generated from module ownership;
// it is never read from operator configuration.
func Compose(config model.SiteConfig) (model.Site, []ResolvedModule, error) {
	registry := FirstPartyRegistry()
	resolved, err := registry.Resolve(config)
	if err != nil {
		return model.Site{}, nil, err
	}
	site := config.BaseSite()
	site.Components, err = composeComponents(site.Components, resolved, site)
	if err != nil {
		return model.Site{}, nil, err
	}
	declarations, err := composeDeclarations(site, resolved)
	if err != nil {
		return model.Site{}, nil, err
	}
	site.Declarations = declarations
	for _, declaration := range declarations {
		site.DHCPReservations = append(site.DHCPReservations, declaration.DHCPReservations...)
	}
	site.Modules = make([]model.ResolvedModule, 0, len(resolved))
	for _, module := range resolved {
		definition := module.Definition
		requires := make([]string, 0, len(definition.Requires))
		for _, capability := range definition.Requires {
			requires = append(requires, string(capability))
		}
		provides := make([]string, 0, len(definition.Provides))
		for _, capability := range definition.Provides {
			provides = append(provides, string(capability))
		}
		site.Modules = append(site.Modules, model.ResolvedModule{
			Name: definition.Name, Version: definition.Version, Policy: string(definition.Policy),
			Enabled: module.Enabled, Reason: module.Reason, State: module.State,
			DependsOn: append([]string(nil), definition.DependsOn...), Requires: requires, Provides: provides,
		})
	}
	if err := addGatusEndpointIntents(&site); err != nil {
		return model.Site{}, nil, fmt.Errorf("compose Gatus network contract: %w", err)
	}
	if err := site.Validate(); err != nil {
		return model.Site{}, nil, fmt.Errorf("compose canonical site: %w", err)
	}
	return site, resolved, nil
}

// addGatusEndpointIntents derives the firewall contract from the same
// product-owned service metadata that feeds Gatus. It does not introduce a
// second endpoint configuration surface or grant Gatus access to same-zone
// services that do not cross the firewall boundary.
func addGatusEndpointIntents(site *model.Site) error {
	if !IsEnabled(*site, "gatus") {
		return nil
	}
	var gatus *model.ModuleDeclaration
	for index := range site.Declarations {
		if site.Declarations[index].Module == "gatus" {
			gatus = &site.Declarations[index]
			break
		}
	}
	if gatus == nil {
		return nil
	}
	gatusGuest, ok := moduleComponentReference(*site, "lab-gatus-01")
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	for _, declaration := range site.Declarations {
		if declaration.Module == "gatus" {
			continue
		}
		for _, guest := range declaration.Guests {
			if guest.URL == "" || !guest.ProductOwned || guest.Module == "" || guest.Zone == gatusGuest.Zone {
				continue
			}
			parsed, err := url.Parse(guest.URL)
			if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
				return fmt.Errorf("Gatus endpoint for %s must be an HTTPS URL with a hostname", guest.Name)
			}
			key := guest.Name + "\x00" + parsed.Hostname()
			if seen[key] {
				continue
			}
			seen[key] = true
			gatus.NetworkIntents = append(gatus.NetworkIntents, model.NetworkIntent{
				Source: "lab-gatus-01", Destination: guest.Hostname, Endpoint: guest.URL,
				Protocol: "tcp", Ports: []string{"443"}, Direction: "egress",
				Purpose: "Gatus HTTPS check for " + guest.Name,
			})
		}
	}
	sort.SliceStable(gatus.NetworkIntents, func(i, j int) bool {
		if gatus.NetworkIntents[i].Destination != gatus.NetworkIntents[j].Destination {
			return gatus.NetworkIntents[i].Destination < gatus.NetworkIntents[j].Destination
		}
		return gatus.NetworkIntents[i].Purpose < gatus.NetworkIntents[j].Purpose
	})
	return nil
}

func moduleComponentReference(site model.Site, name string) (model.Component, bool) {
	for _, component := range site.PlatformComponents() {
		if component.Name == name {
			return component, true
		}
	}
	return model.Component{}, false
}

func composeComponents(base []model.Component, resolved []ResolvedModule, site model.Site) ([]model.Component, error) {
	components := append([]model.Component(nil), base...)
	for _, module := range resolved {
		if !module.Enabled {
			continue
		}
		projected, err := moduleGuestProjections(module.Definition, site)
		if err != nil {
			return nil, err
		}
		components = append(components, projected...)
	}
	sort.Slice(components, func(i, j int) bool { return components[i].Name < components[j].Name })
	return components, nil
}

// moduleGuestProjections is the single projection boundary for first-party
// guest definitions. The same generated guest data feeds Site.Components and
// ModuleDeclaration.Guests so downstream providers cannot invent ownership or
// resource identities from names.
func moduleGuestProjections(definition ModuleDefinition, site model.Site) ([]model.Component, error) {
	components := make([]model.Component, 0, len(definition.Guests))
	for _, component := range definition.Guests {
		if definition.Placement.ZoneType != "" {
			zone, err := site.ZoneForType(definition.Placement.ZoneType)
			if err != nil {
				return nil, fmt.Errorf("module %s placement: %w", definition.Name, err)
			}
			component.Zone = zone.Name
		}
		component.Module = definition.Name
		component.Tags = append(component.Tags, model.TagBoetticher, model.TagManaged, model.TagModule, "module-"+definition.Name, model.ModuleOwnershipTag(definition.Name), model.TagBackup)
		component.SSHUser = model.DefaultAdminSSHUser
		component.SSHPort = 22
		component.Logging = definition.Name != "logging"
		sort.Strings(component.Tags)
		components = append(components, component)
	}
	return components, nil
}

func IsEnabled(site model.Site, name string) bool {
	for _, module := range site.Modules {
		if module.Name == name {
			return module.Enabled
		}
	}
	return false
}
