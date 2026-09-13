package cli

import (
	"errors"
	"github.com/gofastercloud/boetticher/internal/controller/host"
	"github.com/gofastercloud/boetticher/internal/firewallmodule"
)

func managementCompositionPolicy(config host.LabConfig, homeRecovery bool) (*firewallmodule.CompositionPolicy, error) {
	return managementCompositionPolicyWithLookup(config, homeRecovery, host.LocalControllerLABBinding)
}

func managementCompositionPolicyWithLookup(config host.LabConfig, homeRecovery bool, lookup func(host.LabConfig) (host.ControllerLABBinding, error)) (*firewallmodule.CompositionPolicy, error) {
	policy := &firewallmodule.CompositionPolicy{}
	if config.Network != nil && config.Network.ProtectedRanges != nil {
		r := config.Network.ProtectedRanges
		policy.ProtectedIPv4 = []string{r.Infra, r.Servers, r.Trusted, r.Sandbox}
	}
	binding, err := lookup(config)
	if err == nil {
		policy.ControllerLABAddress, policy.ControllerLABMAC = binding.Address, binding.MAC
		return policy, nil
	}
	if errors.Is(err, host.ErrNoControllerLABBinding) && homeRecovery && config.Proxmox.ConnectionAddress == "" {
		return policy, nil
	}
	return nil, err
}
