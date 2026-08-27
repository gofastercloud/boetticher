package pulse

import (
	"fmt"

	"github.com/gofastercloud/boetticher/internal/model"
)

// Plan is the bounded monitoring projection consumed by Core and Ansible.
// Pulse owns live inventory, metrics, alerts, and availability checks; Core
// retains ownership and semantic verification of the platform model.
type Plan struct {
	ModelRevision       string              `json:"model_revision"`
	Target              string              `json:"target"`
	ManagedBy           string              `json:"managed_by"`
	PlatformOnly        bool                `json:"platform_only"`
	PersistentStatePath string              `json:"persistent_state_path"`
	Components          []model.Component   `json:"components"`
	AvailabilityChecks  []AvailabilityCheck `json:"availability_checks"`
}

type AvailabilityCheck struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	Protocol    string `json:"protocol"`
	Description string `json:"description"`
}

func PlanFromSite(s model.Site) (Plan, error) {
	if err := s.Validate(); err != nil {
		return Plan{}, err
	}
	revision, err := s.Revision()
	if err != nil {
		return Plan{}, err
	}
	return Plan{
		ModelRevision:       revision,
		Target:              model.PulseVersion,
		ManagedBy:           "boetticher",
		PlatformOnly:        true,
		PersistentStatePath: "/var/lib/pulse",
		Components:          s.PlatformComponents(),
		AvailabilityChecks:  platformAvailabilityChecks(s.Network.Domain),
	}, nil
}

func platformAvailabilityChecks(domain string) []AvailabilityCheck {
	return []AvailabilityCheck{
		{Name: "portal", URL: "https://portal." + domain, Protocol: "https", Description: "Core portal HTTPS availability"},
		{Name: "monitoring", URL: "https://monitor." + domain, Protocol: "https", Description: "Core monitoring HTTPS availability"},
		{Name: "dns01-authoritative", URL: "tcp://10.10.10.10:5353", Protocol: "tcp", Description: "Primary authoritative DNS listener availability"},
		{Name: "dns02-authoritative", URL: "tcp://10.10.10.11:5353", Protocol: "tcp", Description: "Secondary authoritative DNS listener availability"},
	}
}

func (p Plan) Validate() error {
	if !p.PlatformOnly || p.ManagedBy != "boetticher" || p.Target != model.PulseVersion {
		return fmt.Errorf("monitoring plan is not the bounded Pulse projection")
	}
	if p.PersistentStatePath != "/var/lib/pulse" {
		return fmt.Errorf("monitoring plan has unexpected persistent state path %q", p.PersistentStatePath)
	}
	return nil
}
