package model

import (
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"
)

// MigrateLegacyStreamDeckConfig removes the 0.4 StreamDeck module and its
// controller-owned USB bindings from a site document. It returns a normal
// 0.5 configuration; the caller remains responsible for proving and removing
// the old guest through the authenticated Proxmox boundary.
func MigrateLegacyStreamDeckConfig(data []byte) (config SiteConfig, removedBindings int, found bool, err error) {
	var document map[string]any
	if err := yaml.Unmarshal(data, &document); err != nil {
		return SiteConfig{}, 0, false, fmt.Errorf("decode legacy site.yml: %w", err)
	}
	modules, ok := document["modules"]
	if ok {
		moduleMap, ok := modules.(map[string]any)
		if !ok {
			return SiteConfig{}, 0, false, errors.New("legacy site.yml: modules expected a mapping")
		}
		if _, ok := moduleMap["streamdeck"]; ok {
			delete(moduleMap, "streamdeck")
			found = true
		}
	}
	if exports, ok := document["usb_exports"]; ok {
		list, ok := exports.([]any)
		if !ok {
			return SiteConfig{}, 0, false, errors.New("legacy site.yml: usb_exports expected a list")
		}
		filtered := make([]any, 0, len(list))
		for index, item := range list {
			binding, ok := item.(map[string]any)
			if !ok {
				return SiteConfig{}, 0, false, fmt.Errorf("legacy site.yml: usb_exports[%d] expected a mapping", index)
			}
			module, ok := binding["module"].(string)
			if !ok {
				return SiteConfig{}, 0, false, fmt.Errorf("legacy site.yml: usb_exports[%d].module expected a string", index)
			}
			if module == "streamdeck" {
				removedBindings++
				found = true
				continue
			}
			filtered = append(filtered, item)
		}
		document["usb_exports"] = filtered
	}
	if !found {
		return SiteConfig{}, 0, false, errors.New("site.yml does not contain legacy StreamDeck state")
	}
	if _, ok := document["companion"]; !ok {
		document["companion"] = map[string]any{
			"enabled":     true,
			"display":     map[string]any{"enabled": true},
			"streamdeck":  map[string]any{"enabled": true},
			"pulse_agent": map[string]any{"enabled": true},
		}
	}
	migrated, err := yaml.Marshal(document)
	if err != nil {
		return SiteConfig{}, 0, false, fmt.Errorf("encode migrated site.yml: %w", err)
	}
	config, err = ParseSiteConfig(migrated)
	if err != nil {
		return SiteConfig{}, 0, false, fmt.Errorf("validate migrated site.yml: %w", err)
	}
	config.PlatformVersion = PlatformVersion
	config.SchemaVersion = SchemaVersion
	if err := config.Validate(); err != nil {
		return SiteConfig{}, 0, false, fmt.Errorf("validate migrated 0.5 site.yml: %w", err)
	}
	return config, removedBindings, true, nil
}
