package cli

import (
	"errors"
	"github.com/gofastercloud/boetticher/internal/controller/host"
	"testing"
)

func TestManagementCompositionPolicy(t *testing.T) {
	c := host.LabConfig{Proxmox: host.ProxmoxConfig{ConnectionAddress: "10.10.99.5"}, Network: &host.NetworkConfig{ProtectedRanges: &host.ProtectedRanges{Infra: "10.10.10.224/28", Servers: "10.10.20.224/28", Trusted: "10.10.30.224/28", Sandbox: "10.10.40.224/28"}}}
	p, err := managementCompositionPolicyWithLookup(c, false, func(host.LabConfig) (host.ControllerLABBinding, error) {
		return host.ControllerLABBinding{Address: "10.10.20.61", MAC: "02:00:00:00:14:3d"}, nil
	})
	if err != nil || p.ControllerLABAddress != "10.10.20.61" || len(p.ProtectedIPv4) != 4 {
		t.Fatalf("policy=%+v err=%v", p, err)
	}
	_, err = managementCompositionPolicyWithLookup(host.LabConfig{Proxmox: host.ProxmoxConfig{ConnectionAddress: "10.10.99.5"}}, false, func(host.LabConfig) (host.ControllerLABBinding, error) {
		return host.ControllerLABBinding{}, host.ErrNoControllerLABBinding
	})
	if !errors.Is(err, host.ErrNoControllerLABBinding) {
		t.Fatalf("expected refusal, got %v", err)
	}
	p, err = managementCompositionPolicyWithLookup(host.LabConfig{}, true, func(host.LabConfig) (host.ControllerLABBinding, error) {
		return host.ControllerLABBinding{}, host.ErrNoControllerLABBinding
	})
	if err != nil || p == nil {
		t.Fatalf("fresh bootstrap should omit binding: %+v %v", p, err)
	}
}
