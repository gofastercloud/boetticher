package modules

import (
	"fmt"
	"sort"

	"github.com/gofastercloud/boetticher/internal/model"
)

// SecretDeclarations returns the secret contract for a module. Disabled
// modules are reconstructed in memory so an operator can prepare their
// encrypted state before enabling them; no site configuration is persisted.
func SecretDeclarations(config model.SiteConfig, name string) ([]model.SecretDeclaration, error) {
	if _, ok := FirstPartyRegistry().Definition(name); !ok {
		return nil, fmt.Errorf("unknown first-party module %q", name)
	}

	resolvedSite, _, err := Compose(config)
	if err != nil {
		return nil, err
	}
	if declaration, ok := declarationByName(resolvedSite.Declarations, name); ok {
		return sortedSecretDeclarations(declaration.Secrets), nil
	}

	// Project the declaration directly for an inactive module. Enabling it in
	// the full registry can create an unrelated capability conflict (for
	// example, a deliberately disabled managed firewall in external mode),
	// while its secret contract is still unambiguous.
	base := config.BaseSite()
	base.ModuleConfig = config.Modules.Map()
	for _, definition := range FirstPartyRegistry().Definitions() {
		requested, exists := base.ModuleConfig[definition.Name]
		enabled := defaultEnabled(definition.Policy)
		if exists && requested.Enabled != nil {
			enabled = *requested.Enabled
		}
		base.Modules = append(base.Modules, model.ResolvedModule{Name: definition.Name, Enabled: enabled})
	}
	if name == "litellm" {
		configured, exists := base.ModuleConfig[name]
		if !exists || len(configured.Upstreams) == 0 || len(configured.Models) == 0 {
			return nil, fmt.Errorf("module litellm requires configured upstreams and model aliases before its secret names are known")
		}
		if err := model.ValidateLiteLLMConfig(configured); err != nil {
			return nil, err
		}
	}
	definition, _ := FirstPartyRegistry().Definition(name)
	declaration, err := declarationFor(definition, base)
	if err != nil {
		return nil, fmt.Errorf("resolve secret declarations for module %s: %w", name, err)
	}
	return sortedSecretDeclarations(declaration.Secrets), nil
}

// AllSecretDeclarations returns the composed secret contracts for active
// modules plus explicitly configured inactive modules. Default-off modules
// with no configuration have no legal secret names until their configuration
// supplies a declaration (LiteLLM is the notable example).
func AllSecretDeclarations(config model.SiteConfig) ([]model.ModuleDeclaration, error) {
	resolvedSite, _, err := Compose(config)
	if err != nil {
		return nil, err
	}
	byModule := make(map[string]model.ModuleDeclaration, len(resolvedSite.Declarations))
	for _, declaration := range resolvedSite.Declarations {
		declaration.Secrets = sortedSecretDeclarations(declaration.Secrets)
		byModule[declaration.Module] = declaration
	}
	configured := config.Modules.Map()
	names := make([]string, 0, len(configured))
	for name := range configured {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, exists := byModule[name]; exists {
			continue
		}
		secrets, err := SecretDeclarations(config, name)
		if err != nil {
			return nil, err
		}
		byModule[name] = model.ModuleDeclaration{Module: name, Secrets: secrets}
	}
	result := make([]model.ModuleDeclaration, 0, len(byModule))
	for _, declaration := range byModule {
		if len(declaration.Secrets) == 0 {
			continue
		}
		result = append(result, declaration)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Module < result[j].Module })
	return result, nil
}

func declarationByName(declarations []model.ModuleDeclaration, name string) (model.ModuleDeclaration, bool) {
	for _, declaration := range declarations {
		if declaration.Module == name {
			return declaration, true
		}
	}
	return model.ModuleDeclaration{}, false
}

func sortedSecretDeclarations(values []model.SecretDeclaration) []model.SecretDeclaration {
	byName := make(map[string]model.SecretDeclaration, len(values))
	for _, value := range values {
		if _, exists := byName[value.Name]; !exists {
			byName[value.Name] = value
		}
	}
	result := make([]model.SecretDeclaration, 0, len(byName))
	for _, value := range byName {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}
