package cli

import "github.com/gofastercloud/boetticher/internal/model"

func findManagedEndpoint(s model.Site, wanted string) (model.Component, bool) {
	for _, component := range managedEndpointComponents(s) {
		if component.Name == wanted || component.Hostname == wanted {
			return component, true
		}
		for _, alias := range component.DNSAliases {
			if alias == wanted {
				return component, true
			}
		}
	}
	return model.Component{}, false
}

func managedEndpointComponents(s model.Site) []model.Component {
	components := s.PlatformComponents()
	known := make(map[string]struct{}, len(components))
	for _, component := range components {
		known[component.Name] = struct{}{}
	}
	for _, retained := range s.RetainedModules {
		for _, component := range retained.Guests {
			if _, exists := known[component.Name]; exists {
				continue
			}
			components = append(components, component)
			known[component.Name] = struct{}{}
		}
	}
	return components
}
