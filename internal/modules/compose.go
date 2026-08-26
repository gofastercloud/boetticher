package modules

import (
	"fmt"
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
	site.Components = composeComponents(site.Components, resolved)
	declarations, err := composeDeclarations(site, resolved)
	if err != nil {
		return model.Site{}, nil, err
	}
	site.Declarations = declarations
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
	if err := site.Validate(); err != nil {
		return model.Site{}, nil, fmt.Errorf("compose canonical site: %w", err)
	}
	return site, resolved, nil
}

func composeComponents(base []model.Component, resolved []ResolvedModule) []model.Component {
	components := append([]model.Component(nil), base...)
	for _, module := range resolved {
		if !module.Enabled {
			continue
		}
		for _, component := range module.Definition.Components {
			component.Module = module.Definition.Name
			component.Tags = append(component.Tags, model.TagBoetticher, model.TagManaged, model.TagModule, "module-"+module.Definition.Name, model.TagBackup)
			component.SSHUser = model.DefaultAdminSSHUser
			component.SSHPort = 22
			component.Logging = module.Definition.Name != "logging"
			sort.Strings(component.Tags)
			components = append(components, component)
		}
	}
	sort.Slice(components, func(i, j int) bool { return components[i].Name < components[j].Name })
	return components
}

func IsEnabled(site model.Site, name string) bool {
	for _, module := range site.Modules {
		if module.Name == name {
			return module.Enabled
		}
	}
	return false
}
