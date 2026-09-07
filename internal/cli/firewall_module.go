package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"github.com/gofastercloud/boetticher/internal/controllerstatus"
	"github.com/gofastercloud/boetticher/internal/firewallmodule"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/openwrt"
)

func runFirewallCapability(action string, args []string, input io.Reader, out, errOut io.Writer) error {
	switch action {
	case "plan":
		return runFirewallPlan(args, out)
	case "apply":
		return runFirewallApply(args, input, out, errOut)
	case "status":
		return runFirewallStatus(args, out)
	case "teardown":
		return runFirewallTeardown(args, input, out, errOut)
	case "reboot":
		return runFirewallReboot(args, input, out)
	default:
		return fmt.Errorf("module capability %q does not implement action %q", "firewall", action)
	}
}

type firewallCommandOptions struct{ yes bool }

func parseFirewallOptions(command string, args []string, destructive bool) (firewallCommandOptions, error) {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	options := firewallCommandOptions{}
	fs.BoolVar(&options.yes, "yes", false, "approve the firewall capability change")
	if err := fs.Parse(args); err != nil {
		return firewallCommandOptions{}, err
	}
	if fs.NArg() != 0 {
		suffix := "[--yes]"
		if destructive {
			suffix = "[--yes]"
		}
		return firewallCommandOptions{}, fmt.Errorf("usage: boetticher module firewall %s %s", command, suffix)
	}
	return options, nil
}

func loadFirewallContext() (model.Site, firewallmodule.DesiredState, firewallmodule.HostClient, error) {
	hostConfig, err := controllerhost.LoadConfig()
	if err != nil {
		return model.Site{}, firewallmodule.DesiredState{}, firewallmodule.HostClient{}, err
	}
	configuredNetwork := controllerhost.DefaultNetworkConfig()
	if hostConfig.Network != nil {
		configuredNetwork = *hostConfig.Network
	}
	if err := controllerhost.ValidateNetworkConfig(configuredNetwork); err != nil {
		return model.Site{}, firewallmodule.DesiredState{}, firewallmodule.HostClient{}, fmt.Errorf("validate Host network intent: %w", err)
	}
	reference := controllerhost.DefaultNetworkConfig()
	if configuredNetwork.VLANs != reference.VLANs {
		return model.Site{}, firewallmodule.DesiredState{}, firewallmodule.HostClient{}, errors.New("Host VLAN intent does not match the six-zone firewall contract; run or fix host apply")
	}
	current := model.NewSite(hostConfig.Name, "controller-local", model.GatewayModeManaged)
	desired, err := firewallmodule.DesiredFromSite(current)
	if err != nil {
		return model.Site{}, firewallmodule.DesiredState{}, firewallmodule.HostClient{}, fmt.Errorf("validate firewall network intent: %w", err)
	}
	transport, err := controllerhost.TransportFor(hostConfig)
	if err != nil {
		return model.Site{}, firewallmodule.DesiredState{}, firewallmodule.HostClient{}, err
	}
	// ImageBuilder and first boot are deliberately bounded but can exceed the
	// short default used by ordinary Host status commands.
	transport.Timeout = 10 * time.Minute
	return current, desired, firewallmodule.HostClient{Transport: transport}, nil
}

func runFirewallPlan(args []string, out io.Writer) error {
	if _, err := parseFirewallOptions("module firewall plan", args, false); err != nil {
		return err
	}
	_, desired, host, err := loadFirewallContext()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := firewallmodule.ValidateHostSubstrateViaSSH(ctx, host); err != nil {
		return err
	}
	provider, err := firewallmodule.InspectHostProvider(ctx, host)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "Firewall plan")
	if !provider.Exists {
		fmt.Fprintf(out, "\nCreate:\n  provider %s\n  six LAB IPv4 gateways\n  reference zone firewall policy\n  ordinary Internet NAT\n", firewallmodule.ProviderName)
	} else {
		fmt.Fprintf(out, "\nPreserve:\n  provider %s\n", firewallmodule.ProviderName)
		fmt.Fprintln(out, "  existing provider-native state outside Boetticher-owned sections")
		fmt.Fprintln(out, "Update if required:\n  six LAB IPv4 gateways\n  reference zone firewall policy\n  ordinary Internet NAT")
	}
	fmt.Fprintln(out, "\nPreserve:\n  Controller\n  Host enrollment and SSH trust\n  vmbr0\n  vmbr1\n  boetticher-data\n  physical networking")
	fmt.Fprintln(out, "\nDHCP: not configured\nDNS: not configured")
	_ = desired
	return nil
}

func runFirewallApply(args []string, input io.Reader, out, errOut io.Writer) (err error) {
	options, err := parseFirewallOptions("module firewall apply", args, false)
	if err != nil {
		return err
	}
	current, desired, host, err := loadFirewallContext()
	if err != nil {
		return err
	}
	controllerstatus.NotifyBestEffort(controllerstatus.OperationEvent{Event: "operation-start", Name: "firewall apply", Steps: 7})
	defer func() {
		if err != nil {
			controllerstatus.NotifyBestEffort(controllerstatus.OperationEvent{Event: "operation-failure", Name: "firewall apply", Detail: err.Error()})
			return
		}
		controllerstatus.NotifyBestEffort(controllerstatus.OperationEvent{Event: "operation-success", Name: "firewall apply"})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	if err := firewallmodule.ValidateHostSubstrateViaSSH(ctx, host); err != nil {
		return err
	}
	controllerstatus.NotifyBestEffort(controllerstatus.OperationEvent{Event: "operation-progress", Name: "firewall apply", CurrentStep: 1, TotalSteps: 7, Detail: "Host substrate verified"})
	providerStatus, err := firewallmodule.InspectHostProvider(ctx, host)
	if err != nil {
		return err
	}
	bootstrapNeeded := !providerStatus.Exists || !strings.Contains(providerStatus.Config, "scsi0:")
	if !providerStatus.Exists && !options.yes {
		if input == nil {
			return errors.New("firewall apply requires --yes or an interactive confirmation")
		}
		answer, promptErr := promptYesNo(bufio.NewReader(input), out, "Create the firewall provider and change LAB routing? [y/N]: ", false)
		if promptErr != nil {
			return promptErr
		}
		if !answer {
			return errors.New("firewall apply cancelled")
		}
	}
	stateDir := firewallmodule.StateDir(current)
	credential := ""
	if providerStatus.Exists {
		credential, err = firewallmodule.LoadCredential(stateDir)
		if err != nil {
			return fmt.Errorf("load firewall provider credential: %w", err)
		}
	} else {
		credential, _, err = firewallmodule.EnsureCredential(stateDir)
		if err != nil {
			return err
		}
		controllerstatus.NotifyBestEffort(controllerstatus.OperationEvent{Event: "operation-progress", Name: "firewall apply", CurrentStep: 2, TotalSteps: 7, Detail: "Provider image ready"})
	}
	var image firewallmodule.Image
	if bootstrapNeeded {
		hash, hashErr := firewallmodule.PasswordHash(ctx, credential)
		if hashErr != nil {
			return hashErr
		}
		builder := os.Getenv("BOETTICHER_OPENWRT_BUILDER")
		if builder == "" {
			builder = "/opt/boetticher/current/controller/proxmox/libexec/boetticher-build-openwrt-firewall"
		}
		image, err = firewallmodule.EnsureImageViaHost(ctx, host, firewallmodule.ImageSpec{CacheDir: filepath.Join(stateDir, "image-cache"), ManagementAddress: desired.ManagementAddress, ManagementNetmask: desired.ManagementNetmask, ManagementGateway: desired.ManagementGateway, ControllerAddress: desired.ControllerAddress, PasswordHash: hash, BuilderScript: builder})
		if err != nil {
			return err
		}
	}
	if !providerStatus.Exists {
		fmt.Fprintf(out, "Firewall:\n  Provider: creating %s\n", firewallmodule.ProviderName)
	}
	result, err := firewallmodule.EnsureHostProvider(ctx, host, "boetticher-data", image)
	if err != nil {
		return err
	}
	controllerstatus.NotifyBestEffort(controllerstatus.OperationEvent{Event: "operation-progress", Name: "firewall apply", CurrentStep: 3, TotalSteps: 7, Detail: "Provider running"})
	trust, trustErr := firewallmodule.LoadTrust(stateDir)
	if errors.Is(trustErr, os.ErrNotExist) && bootstrapNeeded {
		trust, err = captureProviderTrust(ctx, host)
		if err != nil {
			return err
		}
		if err := firewallmodule.StoreTrust(stateDir, trust); err != nil {
			return err
		}
	} else if trustErr != nil {
		return fmt.Errorf("load firewall provider TLS trust: %w", trustErr)
	}
	controllerstatus.NotifyBestEffort(controllerstatus.OperationEvent{Event: "operation-progress", Name: "firewall apply", CurrentStep: 4, TotalSteps: 7, Detail: "Provider trust established"})
	provider, err := openwrt.NewClient(openwrt.Config{BaseURL: "https://" + desired.ManagementAddress, Username: "boetticher", Password: credential, TrustPEM: trust})
	if err != nil {
		return err
	}
	controllerstatus.NotifyBestEffort(controllerstatus.OperationEvent{Event: "operation-progress", Name: "firewall apply", CurrentStep: 5, TotalSteps: 7, Detail: "Network reconciled"})
	networkCurrent, err := provider.UCIGet(ctx, "network")
	if err != nil {
		return err
	}
	controllerstatus.NotifyBestEffort(controllerstatus.OperationEvent{Event: "operation-progress", Name: "firewall apply", CurrentStep: 6, TotalSteps: 7, Detail: "Firewall policy reconciled"})
	networkChanges, err := firewallmodule.ReconcileOwned(ctx, provider, "network", networkCurrent, desired.Network)
	if err != nil {
		return err
	}
	firewallCurrent, err := provider.UCIGet(ctx, "firewall")
	if err != nil {
		return err
	}
	firewallChanges, err := firewallmodule.ReconcileOwned(ctx, provider, "firewall", firewallCurrent, desired.Firewall)
	if err != nil {
		return err
	}
	health, err := firewallmodule.CheckHealthViaSSH(ctx, host, desired, provider)
	if err != nil {
		return fmt.Errorf("verify firewall provider runtime: %w", err)
	}
	if !health.Healthy() {
		return fmt.Errorf("verify firewall provider runtime: %s", health.Detail())
	}
	controllerstatus.NotifyBestEffort(controllerstatus.OperationEvent{Event: "operation-progress", Name: "firewall apply", CurrentStep: 7, TotalSteps: 7, Detail: "Firewall runtime verified"})
	if !result.Changed && networkChanges == 0 && firewallChanges == 0 {
		fmt.Fprintln(out, "Firewall: No changes required.")
		return nil
	}
	fmt.Fprintf(out, "  Management: established\n  Network: applied (%d change(s))\n  Policy: applied (%d change(s))\n  Firewall: ready\n\nFirewall: PASS\n", networkChanges, firewallChanges)
	_ = errOut
	return nil
}

func runFirewallStatus(args []string, out io.Writer) error {
	if _, err := parseFirewallOptions("module firewall status", args, false); err != nil {
		return err
	}
	current, desired, host, err := loadFirewallContext()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	status, err := firewallmodule.InspectHostProvider(ctx, host)
	if err != nil {
		return err
	}
	if !status.Exists {
		fmt.Fprintln(out, "Firewall: FAIL\nProvider: absent")
		return errors.New("firewall provider is absent")
	}
	credential, err := firewallmodule.LoadCredential(firewallmodule.StateDir(current))
	if err != nil {
		return err
	}
	trust, err := firewallmodule.LoadTrust(firewallmodule.StateDir(current))
	if err != nil {
		return err
	}
	provider, err := openwrt.NewClient(openwrt.Config{BaseURL: "https://" + desired.ManagementAddress, Username: "boetticher", Password: credential, TrustPEM: trust})
	if err != nil {
		return err
	}
	health, err := firewallmodule.CheckHealthViaSSH(ctx, host, desired, provider)
	if err != nil {
		return err
	}
	if !health.Healthy() {
		fmt.Fprintf(out, "Firewall: FAIL\nProvider: %s\n%s\n", firewallmodule.ProviderSummary(health.Provider), health.Detail())
		return errors.New("firewall provider health check failed")
	}
	fmt.Fprintf(out, "Firewall: PASS\nProvider: %s\nManagement: reachable\nGateways: %d/%d present\nFirewall: active\nInternet route: active\n", firewallmodule.ProviderSummary(health.Provider), health.GatewaysPresent, health.GatewaysExpected)
	return nil
}

func runFirewallTeardown(args []string, input io.Reader, out, errOut io.Writer) error {
	options, err := parseFirewallOptions("module firewall teardown", args, true)
	if err != nil {
		return err
	}
	current, _, host, err := loadFirewallContext()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	if err := firewallmodule.ValidateHostSubstrateViaSSH(ctx, host); err != nil {
		return err
	}
	status, err := firewallmodule.InspectHostProvider(ctx, host)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Firewall teardown will remove:\n  %s\n  its provider disk\n  Controller-owned provider credential and TLS trust\n\nIt will preserve:\n  Controller\n  Host\n  vmbr0\n  vmbr1\n  boetticher-data\n  physical networking\n", firewallmodule.ProviderName)
	if !options.yes {
		if input == nil {
			return errors.New("firewall teardown requires --yes or an interactive confirmation")
		}
		answer, promptErr := promptYesNo(bufio.NewReader(input), out, "Remove the firewall provider? [y/N]: ", false)
		if promptErr != nil {
			return promptErr
		}
		if !answer {
			return errors.New("firewall teardown cancelled")
		}
	}
	if status.Exists {
		if err := firewallmodule.DestroyHostProvider(ctx, host, "boetticher-data"); err != nil {
			return err
		}
	}
	if err := firewallmodule.RemoveState(firewallmodule.StateDir(current)); err != nil {
		return err
	}
	fmt.Fprintln(out, "Firewall teardown: PASS")
	_ = errOut
	return nil
}

func runFirewallReboot(args []string, input io.Reader, out io.Writer) error {
	options, err := parseFirewallOptions("module firewall reboot", args, true)
	if err != nil {
		return err
	}
	_, _, host, err := loadFirewallContext()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := firewallmodule.ValidateHostSubstrateViaSSH(ctx, host); err != nil {
		return err
	}
	if !options.yes {
		if input == nil {
			return errors.New("firewall reboot requires --yes or an interactive confirmation")
		}
		answer, promptErr := promptYesNo(bufio.NewReader(input), out, "Reboot the firewall provider? [y/N]: ", false)
		if promptErr != nil {
			return promptErr
		}
		if !answer {
			return errors.New("firewall reboot cancelled")
		}
	}
	if err := firewallmodule.RebootHostProvider(ctx, host, "boetticher-data"); err != nil {
		return err
	}
	fmt.Fprintln(out, "Firewall provider reboot: PASS")
	return nil
}

func captureProviderTrust(ctx context.Context, host firewallmodule.HostClient) ([]byte, error) {
	deadline := time.Now().Add(90 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		trust, err := firewallmodule.CaptureProviderTrustViaHost(ctx, host)
		if err == nil {
			return trust, nil
		}
		last = err
		time.Sleep(2 * time.Second)
	}
	return nil, fmt.Errorf("provider TLS bootstrap timeout: %w", last)
}
