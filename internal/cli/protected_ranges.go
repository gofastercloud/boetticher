package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"github.com/gofastercloud/boetticher/internal/firewallmodule"
)

var canonicalProtectedRanges = controllerhost.ProtectedRanges{
	Infra: "10.10.10.224/28", Servers: "10.10.20.224/28", Trusted: "10.10.30.224/28", Sandbox: "10.10.40.224/28",
}

// adoptProtectedRanges observes every bounded source before the firewall can
// be provisioned or reconciled. Unknown guests and unreadable native state are
// conflicts; absence is never treated as proof that a range is empty.
func adoptProtectedRanges(ctx context.Context, config controllerhost.LabConfig, host firewallmodule.HostClient, provider firewallmodule.HostProviderStatus) (controllerhost.ProtectedRangeObservations, error) {
	observations := controllerhost.ProtectedRangeObservations{}
	if config.Modules.DHCP != nil {
		for _, reservation := range config.Modules.DHCP.Reservations {
			observations.Reservations = append(observations.Reservations, reservation.Address)
		}
	}
	attachments, err := readProtectedRangeAttachments(ctx, host)
	if err != nil {
		return controllerhost.ProtectedRangeObservations{}, err
	}
	observations.ManagedAttachments = attachments
	if provider.Exists {
		leases, leaseErr := readNativeDHCPLeases(ctx, host)
		if errors.Is(leaseErr, errLeaseFileAbsent) {
			return controllerhost.ProtectedRangeObservations{}, errors.New("protected range adoption cannot prove provider leases are absent: native lease file is unavailable")
		}
		if leaseErr != nil {
			return controllerhost.ProtectedRangeObservations{}, fmt.Errorf("read provider leases for protected range adoption: %w", leaseErr)
		}
		for _, lease := range leases {
			if lease.Expiry == 0 || lease.Expiry > 0 {
				observations.Leases = append(observations.Leases, lease.Address)
			}
		}
		nativeReservations, nativeErr := readNativeDHCPReservations(ctx, host)
		if nativeErr != nil {
			return controllerhost.ProtectedRangeObservations{}, nativeErr
		}
		observations.Reservations = append(observations.Reservations, nativeReservations...)
	}
	return observations, nil
}

func prepareProtectedRanges(ctx context.Context, config controllerhost.LabConfig, host firewallmodule.HostClient, provider firewallmodule.HostProviderStatus, yes, save bool, input io.Reader, out io.Writer) (controllerhost.LabConfig, error) {
	if config.Network != nil && config.Network.ProtectedRanges != nil {
		if err := controllerhost.PrepareProtectedRangeChange(config.Network.ProtectedRanges, config.Network.ProtectedRanges, controllerhost.ProtectedRangeObservations{}); err != nil {
			return controllerhost.LabConfig{}, err
		}
		return config, nil
	}
	observations, err := adoptProtectedRanges(ctx, config, host, provider)
	if err != nil {
		return controllerhost.LabConfig{}, err
	}
	if err := controllerhost.PrepareProtectedRangeChange(nil, &canonicalProtectedRanges, observations); err != nil {
		return controllerhost.LabConfig{}, err
	}
	fmt.Fprintln(out, "Protected ranges: adopt canonical .224-.239 workload class in INFRA/SERVERS/TRUSTED/SANDBOX")
	if save && !yes {
		if input == nil {
			return controllerhost.LabConfig{}, errors.New("protected range adoption requires --yes or an interactive confirmation")
		}
		answer, promptErr := promptYesNo(input, out, "Adopt the verified empty protected ranges? [y/N]: ", false)
		if promptErr != nil {
			return controllerhost.LabConfig{}, promptErr
		}
		if !answer {
			return controllerhost.LabConfig{}, errors.New("protected range adoption cancelled")
		}
	}
	if config.Network == nil {
		network := controllerhost.DefaultNetworkConfig()
		config.Network = &network
	}
	copyRanges := canonicalProtectedRanges
	config.Network.ProtectedRanges = &copyRanges
	if save {
		if err := controllerhost.SaveConfig(config); err != nil {
			return controllerhost.LabConfig{}, fmt.Errorf("save adopted protected ranges: %w", err)
		}
	}
	return config, nil
}

func readProtectedRangeAttachments(ctx context.Context, host firewallmodule.HostClient) ([]string, error) {
	result, err := host.Run(ctx, "set -eu; pvesh get /cluster/resources --type vm --output-format json")
	if err != nil {
		return nil, fmt.Errorf("read Host guest attachments for protected range adoption: %w", err)
	}
	var resources []struct {
		VMID int    `json:"vmid"`
		Type string `json:"type"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(result.Stdout, &resources); err != nil {
		var envelope struct {
			Data []struct {
				VMID int    `json:"vmid"`
				Type string `json:"type"`
				Name string `json:"name"`
			} `json:"data"`
		}
		if envelopeErr := json.Unmarshal(result.Stdout, &envelope); envelopeErr != nil {
			return nil, errors.New("Host guest attachment inventory is malformed")
		}
		resources = envelope.Data
	}
	for _, guest := range resources {
		if guest.VMID == firewallmodule.ProviderVMID {
			continue
		}
		return nil, fmt.Errorf("protected range adoption conflicts with unknown LAB guest attachment VMID %d (%s %s); prove its addresses before retrying", guest.VMID, guest.Type, guest.Name)
	}
	return nil, nil
}

func readNativeDHCPReservations(ctx context.Context, host firewallmodule.HostClient) ([]string, error) {
	result, err := host.Run(ctx, "set -eu; qm guest exec "+fmt.Sprint(firewallmodule.ProviderVMID)+" --synchronous 1 -- /bin/sh -c 'uci -q show dhcp | sed -n \"s/.*\\.ip=\\x27\\([^\\x27]*\\)\\x27.*/\\1/p\"'")
	if err != nil {
		return nil, fmt.Errorf("read provider reservations for protected range adoption: %w", err)
	}
	var response struct {
		ExitCode int    `json:"exitcode"`
		Data     string `json:"out-data"`
		Error    string `json:"err-data"`
	}
	if err := json.Unmarshal(result.Stdout, &response); err != nil {
		return nil, errors.New("provider reservation response is malformed")
	}
	if response.ExitCode != 0 {
		return nil, fmt.Errorf("read provider reservations failed (%d): %s", response.ExitCode, strings.TrimSpace(response.Error))
	}
	addresses := []string{}
	for _, raw := range strings.Fields(response.Data) {
		address, err := netip.ParseAddr(raw)
		if err != nil || !address.Is4() || address.String() != raw {
			return nil, fmt.Errorf("provider reservation address %q is not canonical IPv4", raw)
		}
		addresses = append(addresses, raw)
	}
	return addresses, nil
}
