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

	"github.com/gofastercloud/boetticher/internal/clientservices"
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
	case "test":
		return runFirewallTest(args, input, out, errOut)
	default:
		return fmt.Errorf("module capability %q does not implement action %q", "firewall", action)
	}
}

type firewallCommandOptions struct{ yes bool }

func parseFirewallOptions(command string, args []string, allowYes bool) (firewallCommandOptions, error) {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	options := firewallCommandOptions{}
	if allowYes {
		fs.BoolVar(&options.yes, "yes", false, "approve the firewall capability change")
	}
	if err := fs.Parse(args); err != nil {
		return firewallCommandOptions{}, err
	}
	if fs.NArg() != 0 {
		suffix := ""
		if allowYes {
			suffix = " [--yes]"
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
	if configuredNetwork.Domain == "" {
		configuredNetwork.Domain = model.DefaultDomain
	}
	if err := controllerhost.ValidateNetworkConfig(configuredNetwork); err != nil {
		return model.Site{}, firewallmodule.DesiredState{}, firewallmodule.HostClient{}, fmt.Errorf("validate Host network intent: %w", err)
	}
	reference := controllerhost.DefaultNetworkConfig()
	if configuredNetwork.VLANs != reference.VLANs {
		return model.Site{}, firewallmodule.DesiredState{}, firewallmodule.HostClient{}, errors.New("Host VLAN intent does not match the six-zone firewall contract; run or fix host apply")
	}
	current := model.NewSite(hostConfig.Name, "controller-local", model.GatewayModeManaged)
	current.Network.Domain = configuredNetwork.Domain
	desired, err := firewallmodule.DesiredFromSiteWithServices(current, hostConfig.Modules)
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
	current, desired, host, err := loadFirewallContext()
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
		changes, err := firewallPlanChanges(ctx, current, desired)
		if err != nil {
			return err
		}
		if len(changes) == 0 && provider.Running && strings.Contains(provider.Config, "scsi0:") {
			fmt.Fprintln(out, "\nNo changes required.")
		} else {
			fmt.Fprintln(out, "\nChanges:")
			if !provider.Running {
				fmt.Fprintln(out, "  start provider runtime")
			}
			if !strings.Contains(provider.Config, "scsi0:") {
				fmt.Fprintln(out, "  attach owned provider disk")
			}
			for _, change := range changes {
				fmt.Fprintf(out, "  %s %s\n", change.Kind, change.Section.Name)
			}
		}
	}
	fmt.Fprintln(out, "\nPreserve:\n  Controller\n  Host enrollment and SSH trust\n  vmbr0\n  vmbr1\n  boetticher-data\n  physical networking")
	hostConfig, err := controllerhost.LoadConfig()
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "\nDHCP: %s\nDNS: %s\n", clientCapabilityIntentLabel(hostConfig.Modules.DHCP), clientCapabilityIntentLabel(hostConfig.Modules.DNS))
	return nil
}

func firewallPlanChanges(ctx context.Context, current model.Site, desired firewallmodule.DesiredState) ([]firewallmodule.Mutation, error) {
	client, err := firewallProviderClient(current, desired)
	if err != nil {
		return nil, err
	}
	networkCurrent, err := client.UCIGet(ctx, "network")
	if err != nil {
		return nil, err
	}
	firewallCurrent, err := client.UCIGet(ctx, "firewall")
	if err != nil {
		return nil, err
	}
	changes, err := firewallmodule.DiffOwned(networkCurrent, desired.Network)
	if err != nil {
		return nil, err
	}
	firewallChanges, err := firewallmodule.DiffFirewall(firewallCurrent, desired.Firewall)
	if err != nil {
		return nil, err
	}
	changes = append(changes, firewallChanges...)
	return changes, nil
}

func runFirewallApply(args []string, input io.Reader, out, errOut io.Writer) (err error) {
	options, err := parseFirewallOptions("module firewall apply", args, true)
	if err != nil {
		return err
	}
	lock, err := acquireClientServicesLock()
	if err != nil {
		return err
	}
	defer lock.Release()
	current, desired, host, err := loadFirewallContext()
	if err != nil {
		return err
	}
	display := controllerstatus.StartApply("firewall apply", 7)
	defer func() {
		display.End(err)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	if err := firewallmodule.ValidateHostSubstrateViaSSH(ctx, host); err != nil {
		return err
	}
	display.Progress(1, "Host substrate verified")
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
		display.Progress(2, "Provider image ready")
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
	display.Progress(3, "Provider running")
	trust, trustErr := firewallmodule.LoadTrust(stateDir)
	if errors.Is(trustErr, os.ErrNotExist) {
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
	display.Progress(4, "Provider trust established")
	provider, err := openwrt.NewClient(openwrt.Config{BaseURL: "https://" + desired.ManagementAddress, ServerName: firewallmodule.ProviderTLSName, Username: "boetticher", Password: credential, TrustPEM: trust})
	if err != nil {
		return err
	}
	if err := waitProviderAPI(ctx, provider); err != nil {
		return fmt.Errorf("wait for firewall provider management API: %w", err)
	}
	display.Progress(5, "Network reconciled")
	networkCurrent, err := provider.UCIGet(ctx, "network")
	if err != nil {
		return err
	}
	display.Progress(6, "Firewall policy reconciled")
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
	display.Progress(7, "Firewall runtime verified")
	if !result.Changed && networkChanges == 0 && firewallChanges == 0 {
		fmt.Fprintln(out, "Firewall: No changes required.")
		return nil
	}
	fmt.Fprintf(out, "  Management: established\n  Network: applied (%d change(s))\n  Policy: applied (%d change(s))\n  Firewall: ready\n\nFirewall: PASS\n", networkChanges, firewallChanges)
	_ = errOut
	return nil
}

func waitProviderAPI(ctx context.Context, provider *openwrt.Client) error {
	readinessCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var last error
	for {
		if err := provider.Authenticate(readinessCtx); err == nil {
			return nil
		} else {
			last = err
		}
		select {
		case <-readinessCtx.Done():
			return fmt.Errorf("firewall management did not become ready; last failure: %v", last)
		case <-time.After(2 * time.Second):
		}
	}
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
		fmt.Fprintln(out, "Firewall: absent\nProvider: absent")
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
	provider, err := openwrt.NewClient(openwrt.Config{BaseURL: "https://" + desired.ManagementAddress, ServerName: firewallmodule.ProviderTLSName, Username: "boetticher", Password: credential, TrustPEM: trust})
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
	options, err := parseFirewallTeardownOptions(args)
	if err != nil {
		return err
	}
	lock, err := acquireClientServicesLock()
	if err != nil {
		return err
	}
	defer lock.Release()
	current, _, host, err := loadFirewallContext()
	if err != nil {
		return err
	}
	hostConfig, err := controllerhost.LoadConfig()
	if err != nil {
		return err
	}
	if hostConfig.Modules.DNS != nil && clientservices.Enabled(hostConfig.Modules.DNS.Enabled) {
		return errors.New("firewall teardown refused while DNS is enabled; run module dns teardown first")
	}
	if hostConfig.Modules.DHCP != nil && clientservices.Enabled(hostConfig.Modules.DHCP.Enabled) {
		return errors.New("firewall teardown refused while DHCP is enabled; run module dhcp teardown first")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	status, err := firewallmodule.InspectHostProvider(ctx, host)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Firewall teardown will remove:\n  %s\n  its provider disk\n  Controller-owned provider credential and TLS trust\n\nIt will preserve:\n  Controller\n  Host\n  vmbr0\n  vmbr1\n  boetticher-data\n  physical networking\n", firewallmodule.ProviderName)
	if options.plan {
		if status.Exists {
			fmt.Fprintf(out, "\nOwned provider readback:\n  kind %s\n  state %s\n  disk %s\n", status.Kind, providerStateLabel(status.Running), providerDiskFromConfig(status.Config))
		} else {
			fmt.Fprintln(out, "\nOwned provider readback:\n  absent (already clean)")
		}
		fmt.Fprintln(out, "  no mutation or confirmation prompt")
		return nil
	}
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

type firewallTeardownOptions struct {
	yes  bool
	plan bool
}

func parseFirewallTeardownOptions(args []string) (firewallTeardownOptions, error) {
	fs := flag.NewFlagSet("module firewall teardown", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	options := firewallTeardownOptions{}
	fs.BoolVar(&options.yes, "yes", false, "approve firewall provider removal")
	fs.BoolVar(&options.plan, "plan", false, "preview exact owned provider removal")
	if err := fs.Parse(args); err != nil {
		return firewallTeardownOptions{}, err
	}
	if fs.NArg() != 0 {
		return firewallTeardownOptions{}, errors.New("usage: boetticher module firewall teardown [--plan|--yes]")
	}
	if options.plan && options.yes {
		return firewallTeardownOptions{}, errors.New("--plan cannot be combined with --yes")
	}
	return options, nil
}

func providerStateLabel(running bool) string {
	if running {
		return "running"
	}
	return "stopped"
}

func providerDiskFromConfig(config string) string {
	for _, line := range strings.Split(config, "\n") {
		if strings.HasPrefix(line, firewallmodule.ProviderDisk+": ") {
			return strings.TrimSpace(strings.TrimPrefix(line, firewallmodule.ProviderDisk+": "))
		}
	}
	return "not attached"
}

func runFirewallReboot(args []string, input io.Reader, out io.Writer) error {
	options, err := parseFirewallOptions("module firewall reboot", args, true)
	if err != nil {
		return err
	}
	lock, err := acquireClientServicesLock()
	if err != nil {
		return err
	}
	defer lock.Release()
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
