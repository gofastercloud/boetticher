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

type firewallCommandOptions struct {
	yes               bool
	managementAddress string
	homeRecovery      bool
}

func parseFirewallOptions(command string, args []string, allowYes bool) (firewallCommandOptions, error) {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	options := firewallCommandOptions{}
	if allowYes {
		fs.BoolVar(&options.yes, "yes", false, "approve the firewall capability change")
	}
	if command == "module firewall plan" || command == "module firewall apply" {
		fs.StringVar(&options.managementAddress, "management-address", "", "set the HOME firewall management IPv4 address")
	}
	if command == "module firewall plan" || command == "module firewall apply" || command == "module firewall status" || command == "module firewall reboot" {
		fs.BoolVar(&options.homeRecovery, "home-recovery", false, "explicitly use the HOME bootstrap/recovery path")
	}
	if err := fs.Parse(args); err != nil {
		return firewallCommandOptions{}, err
	}
	if fs.NArg() != 0 {
		suffix := ""
		if allowYes {
			suffix = " [--yes] [--management-address IPv4] [--home-recovery]"
		} else if command == "module firewall plan" || command == "module firewall status" || command == "module firewall reboot" {
			suffix = " [--management-address IPv4] [--home-recovery]"
		}
		return firewallCommandOptions{}, fmt.Errorf("usage: boetticher module firewall %s %s", command, suffix)
	}
	return options, nil
}

func loadFirewallContext() (model.Site, firewallmodule.DesiredState, firewallmodule.HostClient, error) {
	return loadFirewallContextWithOptions("", false)
}

func loadFirewallContextWithAddress(address string) (model.Site, firewallmodule.DesiredState, firewallmodule.HostClient, error) {
	return loadFirewallContextWithOptions(address, false)
}

func loadFirewallContextWithOptions(address string, homeRecovery bool) (model.Site, firewallmodule.DesiredState, firewallmodule.HostClient, error) {
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
	if hostConfig.Gateway != nil {
		if hostConfig.Gateway.ManagementAddress != "" {
			current.Gateway.ManagementAddress = hostConfig.Gateway.ManagementAddress
		}
	}
	if address != "" {
		current.Gateway.ManagementAddress = address
	}
	policy, policyErr := managementCompositionPolicy(hostConfig, homeRecovery)
	if policyErr != nil {
		return model.Site{}, firewallmodule.DesiredState{}, firewallmodule.HostClient{}, policyErr
	}
	desired, err := firewallmodule.DesiredFromSiteWithServices(current, hostConfig.Modules, policy)
	if err != nil {
		return model.Site{}, firewallmodule.DesiredState{}, firewallmodule.HostClient{}, fmt.Errorf("validate firewall network intent: %w", err)
	}
	if hostConfig.Modules.VPN != nil && clientservices.Enabled(hostConfig.Modules.VPN.Enabled) {
		profile, _, present, profileErr := loadVPNMaterial(current)
		if profileErr != nil {
			return model.Site{}, firewallmodule.DesiredState{}, firewallmodule.HostClient{}, profileErr
		}
		if !present {
			return model.Site{}, firewallmodule.DesiredState{}, firewallmodule.HostClient{}, errors.New("VPN connection material is unavailable; retain the configured profile before firewall planning or applying")
		}
		projection, projectionErr := vpnProfileProjection(profile)
		if projectionErr != nil {
			return model.Site{}, firewallmodule.DesiredState{}, firewallmodule.HostClient{}, projectionErr
		}
		desired, err = firewallmodule.DesiredFromSiteWithServicesAndVPN(current, hostConfig.Modules, projection, policy)
		if err != nil {
			return model.Site{}, firewallmodule.DesiredState{}, firewallmodule.HostClient{}, err
		}
	}
	var transport controllerhost.Transport
	if homeRecovery {
		transport, err = controllerhost.HomeTransportFor(hostConfig)
	} else {
		if hostConfig.Proxmox.ConnectionAddress != controllerhost.LabHostAddress {
			return model.Site{}, firewallmodule.DesiredState{}, firewallmodule.HostClient{}, errors.New("normal firewall operations require enrolled LAB Host 10.10.99.5; use --home-recovery for bootstrap")
		}
		transport, err = controllerhost.TransportFor(hostConfig)
	}
	if err != nil {
		return model.Site{}, firewallmodule.DesiredState{}, firewallmodule.HostClient{}, err
	}
	// ImageBuilder and first boot are deliberately bounded but can exceed the
	// short default used by ordinary Host status commands.
	transport.Timeout = 10 * time.Minute
	return current, desired, firewallmodule.HostClient{Transport: transport, HomeRecovery: homeRecovery}, nil
}

func runFirewallPlan(args []string, out io.Writer) error {
	options, err := parseFirewallOptions("module firewall plan", args, false)
	if err != nil {
		return err
	}
	current, desired, host, err := loadFirewallContextWithOptions(options.managementAddress, options.homeRecovery)
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
	hostConfig, err := controllerhost.LoadConfig()
	if err != nil {
		return err
	}
	hostConfig, err = prepareProtectedRanges(ctx, hostConfig, host, provider, false, false, nil, out)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "Firewall plan")
	if !provider.Exists {
		fmt.Fprintf(out, "\nCreate:\n  provider %s\n  six LAB IPv4 gateways\n  reference zone firewall policy\n  ordinary Internet NAT\n", firewallmodule.ProviderName)
	} else {
		fmt.Fprintf(out, "\nPreserve:\n  provider %s\n", firewallmodule.ProviderName)
		fmt.Fprintln(out, "  existing provider-native state outside Boetticher-owned sections")
		if provider.Running {
			observed, observeErr := firewallmodule.ProviderManagementAddressViaHost(ctx, host)
			if observeErr != nil {
				return observeErr
			}
			current.Gateway.ManagementAddress = observed
			if observed != desired.ManagementAddress {
				fmt.Fprintf(out, "  migrate HOME management endpoint %s -> %s\n", observed, desired.ManagementAddress)
			}
		}
		changes, err := firewallPlanChanges(ctx, current, desired, host)
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
	fmt.Fprintf(out, "\nDHCP: %s\nDNS: %s\n", clientCapabilityIntentLabel(hostConfig.Modules.DHCP), clientCapabilityIntentLabel(hostConfig.Modules.DNS))
	return nil
}

func firewallPlanChanges(ctx context.Context, current model.Site, desired firewallmodule.DesiredState, host firewallmodule.HostClient) ([]firewallmodule.Mutation, error) {
	mode := providerAccessLAB
	if host.HomeRecovery {
		mode = providerAccessHomeRecovery
	}
	connectionDesired := desired
	if host.HomeRecovery && current.Gateway.ManagementAddress != "" {
		connectionDesired.ManagementAddress = current.Gateway.ManagementAddress
	}
	client, err := providerClientForAccess(current, connectionDesired, host.Transport, mode)
	if err != nil {
		return nil, err
	}
	defer client.Close()
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
	current, desired, host, err := loadFirewallContextWithOptions(options.managementAddress, options.homeRecovery)
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
	hostConfig, err := controllerhost.LoadConfig()
	if err != nil {
		return err
	}
	var observedManagementAddress string
	if providerStatus.Exists && providerStatus.Running && strings.Contains(providerStatus.Config, "scsi0:") {
		observedManagementAddress, err = firewallmodule.ProviderManagementAddressViaHost(ctx, host)
		if err != nil {
			return err
		}
	}
	bootstrapNeeded := !providerStatus.Exists || !strings.Contains(providerStatus.Config, "scsi0:")
	replaceProvider := false
	if providerStatus.Exists && strings.Contains(providerStatus.Config, "scsi0:") {
		ready, readyErr := firewallmodule.ClientServicesImageReady(ctx, host)
		if readyErr != nil {
			return readyErr
		}
		if !ready {
			if observedManagementAddress != "" && observedManagementAddress != desired.ManagementAddress {
				return errors.New("refuse firewall management migration while the existing provider image contract is unavailable")
			}
			replaceProvider = true
			bootstrapNeeded = true
			fmt.Fprintln(out, "Provider image: replacing the owned VM 280 image to establish the current client-services contract")
		}
	}
	if replaceProvider {
		if err := refuseVPNStopWithLiveProtectedGuests(ctx, host, hostConfig.Proxmox.Node, hostConfig.Modules); err != nil {
			return err
		}
	}
	if _, err := prepareProtectedRanges(ctx, hostConfig, host, providerStatus, options.yes, true, input, out); err != nil {
		return err
	}
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
	if replaceProvider {
		if err := refuseVPNStopWithLiveProtectedGuests(ctx, host, hostConfig.Proxmox.Node, hostConfig.Modules); err != nil {
			return err
		}
		if err := firewallmodule.DestroyHostProvider(ctx, host, "boetticher-data"); err != nil {
			return err
		}
		if err := firewallmodule.RemoveTrust(stateDir); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove replaced provider TLS trust: %w", err)
		}
		providerStatus = firewallmodule.HostProviderStatus{}
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
	// Persist an explicit address only after ownership, credentials, and trust
	// are established, but before any provider network migration. This leaves
	// desired intent available for normal apply recovery if reload fails.
	if options.managementAddress != "" {
		if hostConfig.Gateway == nil {
			hostConfig.Gateway = &controllerhost.GatewayConfig{}
		}
		if hostConfig.Gateway.ManagementAddress != desired.ManagementAddress {
			hostConfig.Gateway.ManagementAddress = desired.ManagementAddress
			if err := controllerhost.SaveConfig(hostConfig); err != nil {
				return fmt.Errorf("save firewall management address intent: %w", err)
			}
		}
	}
	observedAddress := observedManagementAddress
	if observedAddress == "" {
		observedAddress, err = firewallmodule.ProviderManagementAddressViaHost(ctx, host)
		if err != nil {
			return err
		}
	}
	if observedAddress != desired.ManagementAddress {
		migrationMode := providerAccessLAB
		if host.HomeRecovery {
			migrationMode = providerAccessHomeRecovery
		}
		migrationDesired := desired
		if host.HomeRecovery {
			migrationDesired.ManagementAddress = observedAddress
		}
		migrationProvider, oldErr := providerClientForAccess(current, migrationDesired, host.Transport, migrationMode)
		if oldErr != nil {
			return oldErr
		}
		defer migrationProvider.Close()
		if err := migrateProviderManagementAddress(ctx, host, migrationProvider, observedAddress, desired.ManagementAddress); err != nil {
			return err
		}
	}
	mode := providerAccessLAB
	if host.HomeRecovery {
		mode = providerAccessHomeRecovery
	}
	provider, err := providerClientForAccess(current, desired, host.Transport, mode)
	if err != nil {
		return err
	}
	defer provider.Close()
	if err := waitProviderAPI(ctx, provider); err != nil {
		return fmt.Errorf("wait for firewall provider management API: %w", err)
	}
	display.Progress(5, "Network reconciled")
	config, err := controllerhost.LoadConfig()
	if err != nil {
		return err
	}
	if config.Network == nil || config.Network.ProtectedRanges == nil {
		return errors.New("protected ranges require explicit Host adoption before firewall mutation")
	}
	policy, err := managementCompositionPolicy(config, host.HomeRecovery)
	if err != nil {
		return err
	}
	composed, err := composeFirewallAppliance(current, config.Modules, policy)
	if err != nil {
		return err
	}
	verify := firewallmodule.ApplianceVerifyCallbacks{
		SafetyBeforeNetwork: func(ctx context.Context) error {
			ok, err := firewallmodule.FirewallSafetyStatusViaHost(ctx, host)
			if err != nil {
				return err
			}
			if !ok {
				return errors.New("provider firewall safety status failed")
			}
			return nil
		},
		NetworkReady: func(ctx context.Context) error {
			dump, err := provider.InterfaceDump(ctx)
			if err != nil {
				return err
			}
			if firewallmodule.GatewayCount(dump, composed.DesiredState) != len(composed.Zones) {
				return errors.New("provider gateway interfaces are not ready")
			}
			return nil
		},
		SafetyAfterNetwork: func(ctx context.Context) error {
			ok, err := firewallmodule.FirewallSafetyStatusViaHost(ctx, host)
			if err != nil {
				return err
			}
			if !ok {
				return errors.New("provider firewall safety status failed after network activation")
			}
			return nil
		},
		RuntimeReapply: provider.ReloadFirewall,
	}
	if _, err := firewallmodule.ReconcileAppliance(ctx, provider, composed, verify); err != nil {
		return err
	}
	display.Progress(6, "Firewall policy reconciled")
	networkChanges, firewallChanges := 1, 1
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

func composeFirewallAppliance(site model.Site, modules clientservices.Modules, policy *firewallmodule.CompositionPolicy) (firewallmodule.ApplianceComposition, error) {
	if modules.VPN != nil && clientservices.Enabled(modules.VPN.Enabled) {
		profile, _, present, err := firewallLoadVPNMaterial(site)
		if err != nil {
			return firewallmodule.ApplianceComposition{}, err
		}
		if !present {
			return firewallmodule.ApplianceComposition{}, errors.New("VPN connection material is unavailable; retain the configured profile before firewall apply")
		}
		projection, err := firewallVPNProfileProjection(profile)
		if err != nil {
			return firewallmodule.ApplianceComposition{}, err
		}
		return firewallmodule.ComposeApplianceWithVPN(site, modules, policy, projection)
	}
	return firewallmodule.ComposeAppliance(site, modules, policy)
}

var firewallLoadVPNMaterial = loadVPNMaterial
var firewallVPNProfileProjection = vpnProfileProjection

func migrateProviderManagementAddress(ctx context.Context, host firewallmodule.HostClient, provider *openwrt.Client, observed, desired string) error {
	if err := provider.Authenticate(ctx); err != nil {
		return fmt.Errorf("authenticate at observed firewall address: %w", err)
	}
	sections, err := provider.UCIGet(ctx, "network")
	if err != nil {
		return err
	}
	section, ok := sections["boetticher_home"]
	if !ok || section.Type != "interface" || section.Options["device"] != "eth0" || section.Options["proto"] != "static" || section.Options["ipaddr"] != observed || section.Options["netmask"] != "255.255.252.0" || section.Options["gateway"] != "192.168.4.1" {
		return errors.New("refuse firewall management migration: owned HOME UCI section is not the pinned contract")
	}
	if err := provider.UCISet(ctx, "network", "boetticher_home", "ipaddr", desired); err != nil {
		return err
	}
	if err := provider.UCICommit(ctx, "network"); err != nil {
		return migrationRecoveryError(ctx, host, desired, fmt.Errorf("commit firewall management address: %w", err))
	}
	if err := provider.ServiceConfigChange(ctx, "network"); err != nil {
		return migrationRecoveryError(ctx, host, desired, fmt.Errorf("reload firewall management network: %w", err))
	}
	return nil
}

func migrationRecoveryError(ctx context.Context, host firewallmodule.HostClient, desired string, cause error) error {
	actual, err := firewallmodule.ProviderManagementAddressViaHost(ctx, host)
	if err == nil && actual == desired {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w; unable to verify post-migration address: %v", cause, err)
	}
	return fmt.Errorf("%w; provider remains at %s", cause, actual)
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
	options, err := parseFirewallOptions("module firewall status", args, false)
	if err != nil {
		return err
	}
	current, desired, host, err := loadFirewallContextWithOptions("", options.homeRecovery)
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
	mode := providerAccessLAB
	if host.HomeRecovery {
		mode = providerAccessHomeRecovery
	}
	provider, err := providerClientForAccess(current, desired, host.Transport, mode)
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
	current, _, host, err := loadFirewallContextWithOptions("", options.homeRecovery)
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
	if err := refuseVPNStopWithLiveProtectedGuests(ctx, host, hostConfig.Proxmox.Node, hostConfig.Modules); err != nil {
		return err
	}
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
		if err := refuseVPNStopWithLiveProtectedGuests(ctx, host, hostConfig.Proxmox.Node, hostConfig.Modules); err != nil {
			return err
		}
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
	yes          bool
	plan         bool
	homeRecovery bool
}

func parseFirewallTeardownOptions(args []string) (firewallTeardownOptions, error) {
	fs := flag.NewFlagSet("module firewall teardown", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	options := firewallTeardownOptions{}
	fs.BoolVar(&options.yes, "yes", false, "approve firewall provider removal")
	fs.BoolVar(&options.plan, "plan", false, "preview exact owned provider removal")
	fs.BoolVar(&options.homeRecovery, "home-recovery", false, "explicitly use the HOME bootstrap/recovery path")
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
	_, _, host, err := loadFirewallContextWithOptions("", options.homeRecovery)
	if err != nil {
		return err
	}
	hostConfig, err := controllerhost.LoadConfig()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := firewallmodule.ValidateHostSubstrateViaSSH(ctx, host); err != nil {
		return err
	}
	if err := refuseVPNStopWithLiveProtectedGuests(ctx, host, hostConfig.Proxmox.Node, hostConfig.Modules); err != nil {
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
	if err := refuseVPNStopWithLiveProtectedGuests(ctx, host, hostConfig.Proxmox.Node, hostConfig.Modules); err != nil {
		return err
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
