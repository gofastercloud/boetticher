package firewallmodule

import (
	"context"
	"errors"
	"fmt"

	"github.com/gofastercloud/boetticher/internal/openwrt"
)

// ApplianceProvider is the small native surface needed by the ordered
// appliance coordinator. Verification is supplied by the caller so this
// package does not invent a second runtime policy implementation.
type ApplianceProvider interface {
	uciWriter
	UCIGet(context.Context, string) (map[string]openwrt.UCISection, error)
	UCICommit(context.Context, string) error
	ServiceConfigChange(context.Context, string) error
	ReloadFirewall(context.Context) error
}

// ApplianceVerifyCallbacks are bounded read-only gates at native trust
// boundaries. Safety runs before network activation; network waits for the
// caller's existing interface readiness check.
type ApplianceVerifyCallbacks struct {
	SafetyBeforeNetwork func(context.Context) error
	NetworkReady        func(context.Context) error
	SafetyAfterNetwork  func(context.Context) error
	RuntimeReapply      func(context.Context) error
}

// ReconcileAppliance applies one complete composition in dependency order.
// It performs no rollback: saved intent remains authoritative on failure.
func ReconcileAppliance(ctx context.Context, provider ApplianceProvider, composition ApplianceComposition, verify ApplianceVerifyCallbacks) (int, error) {
	if provider == nil {
		return 0, errors.New("provider is required")
	}
	if verify.SafetyBeforeNetwork == nil || verify.NetworkReady == nil || verify.SafetyAfterNetwork == nil {
		return 0, errors.New("all appliance verification callbacks are required")
	}
	packages := []struct {
		name    string
		desired []Section
	}{
		{"firewall", composition.Firewall}, {"network", composition.Network},
		{"system", composition.System}, {"stubby", composition.Stubby}, {"dhcp", composition.DHCP},
	}
	current := make(map[string]map[string]openwrt.UCISection, len(packages))
	changes := make(map[string][]Mutation, len(packages))
	for _, item := range packages {
		observed, err := provider.UCIGet(ctx, item.name)
		if err != nil {
			return 0, fmt.Errorf("read provider UCI %s: %w", item.name, err)
		}
		current[item.name] = observed
		if item.name == "firewall" {
			if err := validateFirewallDefaults(observed); err != nil {
				return 0, err
			}
		}
		mutations, err := DiffOwned(observed, item.desired)
		if err != nil {
			return 0, fmt.Errorf("prepare provider UCI %s: %w", item.name, err)
		}
		changes[item.name] = mutations
	}
	if totalMutations(changes) == 0 {
		if err := verifyRuntime(ctx, verify.SafetyBeforeNetwork, verify.RuntimeReapply, "existing firewall safety"); err != nil {
			return 0, err
		}
		if err := verify.NetworkReady(ctx); err != nil {
			return 0, fmt.Errorf("verify existing network readiness: %w", err)
		}
		if err := verify.SafetyAfterNetwork(ctx); err != nil {
			return 0, fmt.Errorf("verify existing firewall safety after network: %w", err)
		}
		return 0, nil
	}
	changed := 0
	if n := changes["firewall"]; len(n) > 0 {
		if _, err := StageOwned(ctx, provider, "firewall", current["firewall"], composition.Firewall); err != nil {
			return changed, err
		}
		if err := provider.UCICommit(ctx, "firewall"); err != nil {
			return changed, err
		}
		if err := provider.ReloadFirewall(ctx); err != nil {
			return changed, err
		}
		changed += len(n)
	}
	if err := verify.SafetyBeforeNetwork(ctx); err != nil {
		return changed, fmt.Errorf("verify firewall safety before network: %w", err)
	}
	if n := changes["network"]; len(n) > 0 {
		if _, err := StageOwned(ctx, provider, "network", current["network"], composition.Network); err != nil {
			return changed, err
		}
		if err := provider.UCICommit(ctx, "network"); err != nil {
			return changed, err
		}
		if err := provider.ServiceConfigChange(ctx, "network"); err != nil {
			return changed, err
		}
		changed += len(n)
	}
	if verify.NetworkReady != nil {
		if err := verify.NetworkReady(ctx); err != nil {
			return changed, fmt.Errorf("verify network readiness: %w", err)
		}
	}
	if err := provider.ReloadFirewall(ctx); err != nil {
		return changed, fmt.Errorf("reload firewall after network readiness: %w", err)
	}
	if verify.SafetyAfterNetwork != nil {
		if err := verify.SafetyAfterNetwork(ctx); err != nil {
			return changed, fmt.Errorf("verify firewall safety after network: %w", err)
		}
	}
	for _, name := range []string{"system", "stubby", "dhcp"} {
		if n := changes[name]; len(n) > 0 {
			if _, err := StageOwned(ctx, provider, name, current[name], sectionFor(composition, name)); err != nil {
				return changed, err
			}
			if err := provider.UCICommit(ctx, name); err != nil {
				return changed, err
			}
			if err := provider.ServiceConfigChange(ctx, name); err != nil {
				return changed, err
			}
			changed += len(n)
		}
	}
	return changed, nil
}

func validateFirewallDefaults(current map[string]openwrt.UCISection) error {
	count := 0
	for name, section := range current {
		if section.Type != "defaults" {
			continue
		}
		count++
		for option, want := range map[string]string{"auto_includes": "1", "flow_offloading": "0", "flow_offloading_hw": "0"} {
			if got, ok := section.Options[option]; ok && got != want {
				return fmt.Errorf("firewall defaults %s.%s conflicts with required value %q", name, option, want)
			}
		}
	}
	if count != 1 {
		return fmt.Errorf("firewall defaults must contain exactly one native defaults section (found %d)", count)
	}
	return nil
}

func totalMutations(all map[string][]Mutation) int {
	total := 0
	for _, changes := range all {
		total += len(changes)
	}
	return total
}

func verifyRuntime(ctx context.Context, verify func(context.Context) error, reapply func(context.Context) error, label string) error {
	if err := verify(ctx); err != nil {
		if reapply == nil {
			return fmt.Errorf("verify %s: %w", label, err)
		}
		if applyErr := reapply(ctx); applyErr != nil {
			return fmt.Errorf("verify %s: %w; runtime reapply failed: %v", label, err, applyErr)
		}
		if retryErr := verify(ctx); retryErr != nil {
			return fmt.Errorf("verify %s after runtime reapply: %w", label, retryErr)
		}
	}
	return nil
}

func sectionFor(composition ApplianceComposition, name string) []Section {
	switch name {
	case "system":
		return composition.System
	case "stubby":
		return composition.Stubby
	case "dhcp":
		return composition.DHCP
	}
	return nil
}
