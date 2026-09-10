package streamdeck

import "time"

// Resource is a bounded Proxmox resource snapshot supplied by the local
// Companion status service.
type Resource struct {
	Name           string
	Kind           string
	PlatformType   string
	Sources        []string
	PlatformScopes []string
	Status         string
	CPU            *float64
	Memory         *float64

	sourceMetadata bool
}

// State is the local Companion snapshot consumed by the display renderer.
type State struct {
	Status     string
	Resources  []Resource
	ReceivedAt time.Time
	Stale      string
}
