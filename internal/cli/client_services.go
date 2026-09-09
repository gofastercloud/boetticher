package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"github.com/gofastercloud/boetticher/internal/firewallmodule"
	"github.com/gofastercloud/boetticher/internal/firewalltest"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/openwrt"
	"github.com/gofastercloud/boetticher/internal/site"
)

func runClientServiceCapability(capability, action string, args []string, input io.Reader, out, errOut io.Writer) error {
	if capability != "dns" && capability != "dhcp" {
		return fmt.Errorf("module capability %q does not implement action %q", capability, action)
	}
	switch action {
	case "plan", "apply", "status", "teardown", "test":
		return runClientServiceLifecycle(capability, action, args, input, out, errOut)
	case "add-reservation":
		if capability != "dhcp" {
			return fmt.Errorf("module capability %q does not implement action %q", capability, action)
		}
		return runDHCPAddReservation(args, input, out)
	case "remove-reservation":
		if capability != "dhcp" {
			return fmt.Errorf("module capability %q does not implement action %q", capability, action)
		}
		return runDHCPRemoveReservation(args, input, out)
	case "list-reservations":
		if capability != "dhcp" {
			return fmt.Errorf("module capability %q does not implement action %q", capability, action)
		}
		return runDHCPListReservations(args, out)
	case "list-leases":
		if capability != "dhcp" {
			return fmt.Errorf("module capability %q does not implement action %q", capability, action)
		}
		return runDHCPListLeases(args, out)
	case "add-record":
		if capability != "dns" {
			return fmt.Errorf("module capability %q does not implement action %q", capability, action)
		}
		return runDNSAddRecord(args, input, out)
	case "remove-record":
		if capability != "dns" {
			return fmt.Errorf("module capability %q does not implement action %q", capability, action)
		}
		return runDNSRemoveRecord(args, input, out)
	case "list-records":
		if capability != "dns" {
			return fmt.Errorf("module capability %q does not implement action %q", capability, action)
		}
		return runDNSListRecords(args, out)
	default:
		return fmt.Errorf("module capability %q does not implement action %q", capability, action)
	}
}

type clientServiceOptions struct {
	yes         bool
	plan        bool
	cleanupOnly bool
}

func parseClientServiceOptions(command string, args []string, allowYes, allowPlan, allowCleanup bool) (clientServiceOptions, error) {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	options := clientServiceOptions{}
	if allowYes {
		fs.BoolVar(&options.yes, "yes", false, "approve the capability change")
	}
	if allowPlan {
		fs.BoolVar(&options.plan, "plan", false, "preview the capability change")
	}
	if allowCleanup {
		fs.BoolVar(&options.cleanupOnly, "cleanup-only", false, "remove only recognised client-service test leftovers")
	}
	if err := fs.Parse(args); err != nil {
		return clientServiceOptions{}, err
	}
	if fs.NArg() != 0 {
		return clientServiceOptions{}, fmt.Errorf("usage: boetticher module %s %s", strings.TrimPrefix(command, "module "), serviceUsageSuffix(allowYes, allowPlan, allowCleanup))
	}
	if options.plan && options.yes {
		return clientServiceOptions{}, errors.New("--plan cannot be combined with --yes")
	}
	if options.plan && options.cleanupOnly {
		return clientServiceOptions{}, errors.New("--plan cannot be combined with --cleanup-only")
	}
	if options.cleanupOnly && !options.yes {
		return clientServiceOptions{}, errors.New("--cleanup-only requires --yes")
	}
	return options, nil
}

func serviceUsageSuffix(allowYes, allowPlan, allowCleanup bool) string {
	parts := []string{}
	if allowPlan {
		parts = append(parts, "--plan")
	}
	if allowYes {
		parts = append(parts, "--yes")
	}
	if allowCleanup {
		parts = append(parts, "--cleanup-only --yes")
	}
	if len(parts) == 0 {
		return ""
	}
	return "[" + strings.Join(parts, "|") + "]"
}

type clientServiceContext struct {
	Config     controllerhost.LabConfig
	Site       model.Site
	Desired    firewallmodule.DesiredState
	Host       firewallmodule.HostClient
	VPNProfile *firewallmodule.VPNProfile
}

func loadClientServiceContext() (clientServiceContext, error) {
	config, err := controllerhost.LoadConfig()
	if err != nil {
		return clientServiceContext{}, err
	}
	current, desired, host, err := loadFirewallContext()
	if err != nil {
		return clientServiceContext{}, err
	}
	serviceContext := clientServiceContext{Config: config, Site: current, Desired: desired, Host: host}
	if config.Modules.VPN != nil && clientservices.Enabled(config.Modules.VPN.Enabled) {
		profile, _, present, materialErr := loadVPNMaterial(current)
		if materialErr == nil && present {
			projection, projectionErr := vpnProfileProjection(profile)
			if projectionErr != nil {
				return clientServiceContext{}, projectionErr
			}
			serviceContext.VPNProfile = &projection
		}
	}
	return serviceContext, nil
}

func acquireClientServicesLock() (*site.OperationLock, error) {
	return site.AcquireOperationLockAt(controllerhost.ClientServicesLockPath)
}

func composeClientAppliance(serviceContext clientServiceContext, modules clientservices.Modules) (firewallmodule.ApplianceComposition, error) {
	if serviceContext.Config.Network == nil || serviceContext.Config.Network.ProtectedRanges == nil {
		return firewallmodule.ApplianceComposition{}, errors.New("protected ranges require explicit Host adoption before client-service mutation")
	}
	ranges := serviceContext.Config.Network.ProtectedRanges
	policy := &firewallmodule.CompositionPolicy{ProtectedIPv4: []string{ranges.Infra, ranges.Servers, ranges.Trusted, ranges.Sandbox}}
	if modules.VPN != nil && clientservices.Enabled(modules.VPN.Enabled) {
		if serviceContext.VPNProfile == nil {
			return firewallmodule.ApplianceComposition{}, errors.New("VPN connection material is unavailable; provision or retain the configured profile before applying")
		}
		return firewallmodule.ComposeApplianceWithVPN(serviceContext.Site, modules, policy, *serviceContext.VPNProfile)
	}
	return firewallmodule.ComposeAppliance(serviceContext.Site, modules, policy)
}

func requireClientProvider(ctx context.Context, current model.Site, desired firewallmodule.DesiredState, host firewallmodule.HostClient) (*openwrt.Client, error) {
	status, err := firewallmodule.InspectHostProvider(ctx, host)
	if err != nil {
		return nil, err
	}
	if !status.Exists {
		return nil, errors.New("firewall provider is absent; run boetticher module firewall apply --yes first")
	}
	provider, err := firewallProviderClient(current, desired)
	if err != nil {
		return nil, err
	}
	if err := waitProviderAPI(ctx, provider); err != nil {
		return nil, fmt.Errorf("firewall management is unavailable: %w", err)
	}
	ready, err := firewallmodule.ClientServicesImageReady(ctx, host)
	if err != nil {
		return nil, err
	}
	if !ready {
		return nil, errors.New("provider image does not contain the current client-services bootstrap contract; replace it through the supported firewall lifecycle before applying DNS or DHCP")
	}
	return provider, nil
}

func reconcileClientServices(ctx context.Context, provider *openwrt.Client, serviceContext clientServiceContext, modules clientservices.Modules) (firewallmodule.ServiceState, int, error) {
	state, err := firewallmodule.ServiceStateFromModules(serviceContext.Site, modules)
	if err != nil {
		return firewallmodule.ServiceState{}, 0, err
	}
	if err := firewallmodule.ValidateServiceState(state); err != nil {
		return firewallmodule.ServiceState{}, 0, err
	}
	composed, err := composeClientAppliance(serviceContext, modules)
	if err != nil {
		return firewallmodule.ServiceState{}, 0, err
	}
	verify := firewallmodule.ApplianceVerifyCallbacks{
		SafetyBeforeNetwork: func(ctx context.Context) error {
			if modules.VPN != nil && clientservices.Enabled(modules.VPN.Enabled) {
				if err := firewallmodule.EnsureVPNIPv6DisabledViaHost(ctx, serviceContext.Host); err != nil {
					return err
				}
			}
			if err := verifyComposedFirewall(ctx, provider, composed.Firewall); err != nil {
				return err
			}
			ok, err := firewallmodule.FirewallSafetyStatusViaHost(ctx, serviceContext.Host)
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
			ok, err := openwrt.DefaultRouteVia(dump, composed.ManagementGateway)
			if err != nil || !ok {
				return errors.New("provider default route is not ready")
			}
			return nil
		},
		SafetyAfterNetwork: func(ctx context.Context) error {
			if modules.VPN != nil && clientservices.Enabled(modules.VPN.Enabled) {
				if err := firewallmodule.EnsureVPNIPv6DisabledViaHost(ctx, serviceContext.Host); err != nil {
					return err
				}
			}
			if err := verifyComposedFirewall(ctx, provider, composed.Firewall); err != nil {
				return err
			}
			ok, err := firewallmodule.FirewallSafetyStatusViaHost(ctx, serviceContext.Host)
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
	changes, err := firewallmodule.ReconcileAppliance(ctx, provider, composed, verify)
	return state, changes, err
}

func verifyComposedFirewall(ctx context.Context, provider *openwrt.Client, desired []firewallmodule.Section) error {
	current, err := provider.UCIGet(ctx, "firewall")
	if err != nil {
		return err
	}
	changes, err := firewallmodule.DiffFirewall(current, desired)
	if err != nil {
		return err
	}
	if len(changes) != 0 {
		names := make([]string, 0, len(changes))
		for _, change := range changes {
			names = append(names, change.Section.Name)
		}
		return fmt.Errorf("provider firewall UCI is not at composed desired state (%d changes: %s)", len(changes), strings.Join(names, ", "))
	}
	return nil
}

func clientServiceChangeCount(ctx context.Context, provider *openwrt.Client, serviceContext clientServiceContext, modules clientservices.Modules) (int, error) {
	composed, err := composeClientAppliance(serviceContext, modules)
	if err != nil {
		return 0, err
	}
	state, err := firewallmodule.ServiceStateFromModules(serviceContext.Site, modules)
	if err != nil {
		return 0, err
	}
	changes := 0
	for _, item := range []struct {
		packageName string
		desired     []firewallmodule.Section
	}{
		{packageName: "system", desired: state.System},
		{packageName: "stubby", desired: state.Stubby},
		{packageName: "dhcp", desired: state.DHCP},
		{packageName: "network", desired: composed.Network},
	} {
		observed, err := provider.UCIGet(ctx, item.packageName)
		if err != nil {
			return 0, err
		}
		if err := firewallmodule.ValidateServicePackage(item.packageName, observed, item.desired); err != nil {
			return 0, err
		}
		itemChanges, diffErr := firewallmodule.DiffOwned(observed, item.desired)
		if diffErr != nil {
			return 0, diffErr
		}
		changes += len(itemChanges)
	}
	observed, err := provider.UCIGet(ctx, "firewall")
	if err != nil {
		return 0, err
	}
	itemChanges, diffErr := firewallmodule.DiffFirewall(observed, composed.Firewall)
	if diffErr != nil {
		return 0, diffErr
	}
	return changes + len(itemChanges), nil
}

func verifyClientServices(ctx context.Context, provider *openwrt.Client, state firewallmodule.ServiceState, capability string, ignoredDHCPSections ...map[string]struct{}) error {
	ignored := map[string]struct{}{}
	if len(ignoredDHCPSections) > 0 {
		ignored = ignoredDHCPSections[0]
	}
	for _, item := range []struct {
		packageName string
		desired     []firewallmodule.Section
	}{
		{packageName: "system", desired: state.System},
		{packageName: "stubby", desired: state.Stubby},
		{packageName: "dhcp", desired: state.DHCP},
	} {
		observed, err := provider.UCIGet(ctx, item.packageName)
		if err != nil {
			return err
		}
		if err := firewallmodule.ValidateServicePackage(item.packageName, observed, item.desired); err != nil {
			return err
		}
		if item.packageName == "dhcp" {
			for _, desired := range item.desired {
				if _, ok := ignored[desired.Name]; !ok {
					continue
				}
				if _, exists := observed[desired.Name]; !exists {
					continue
				}
				// An ignored section is only the exact not-yet-created delta.
				delete(ignored, desired.Name)
			}
		}
		changes, diffErr := firewallmodule.DiffOwned(observed, item.desired)
		if diffErr != nil {
			return diffErr
		}
		if len(changes) > 0 {
			remaining := changes[:0]
			for _, change := range changes {
				if item.packageName == "dhcp" {
					if _, ok := ignored[change.Section.Name]; ok && change.Kind == firewallmodule.MutationCreate {
						continue
					}
				}
				remaining = append(remaining, change)
			}
			if len(remaining) > 0 {
				return fmt.Errorf("provider %s configuration is not at the desired state", item.packageName)
			}
		}
	}
	services, err := provider.ServiceList(ctx)
	if err != nil {
		return err
	}
	observedServices, err := openwrt.ParseServiceList(services)
	if err != nil {
		return err
	}
	if capability == "dns" || capability == "dhcp" || capability == "tailnet" {
		if service, ok := observedServices["dnsmasq"]; !ok || !service.Present || !service.Running || service.Instances == 0 {
			return errors.New("provider dnsmasq service is unavailable")
		}
	}
	if capability == "dns" || capability == "tailnet" {
		if service, ok := observedServices["stubby"]; !ok || !service.Present || !service.Running || service.Instances == 0 {
			return errors.New("provider Stubby encrypted resolver is unavailable")
		}
	}
	if service, ok := observedServices["sysntpd"]; !ok || !service.Present || !service.Running || service.Instances == 0 {
		return errors.New("provider native time service is unavailable")
	}
	return nil
}

func benignDHCPAdditions(ctx context.Context, provider *openwrt.Client, desired []firewallmodule.Section) (bool, error) {
	observed, err := provider.UCIGet(ctx, "dhcp")
	if err != nil {
		return false, err
	}
	mutations, err := firewallmodule.DiffOwned(observed, desired)
	if err != nil {
		return false, err
	}
	if len(mutations) == 0 {
		return false, nil
	}
	for _, mutation := range mutations {
		if mutation.Kind != firewallmodule.MutationCreate || !(strings.HasPrefix(mutation.Section.Name, "boetticher_record_") || strings.HasPrefix(mutation.Section.Name, "boetticher_observability_record_") || strings.HasPrefix(mutation.Section.Name, "boetticher_host_")) {
			return false, nil
		}
	}
	return true, nil
}

func verifyDisabledClientServices(ctx context.Context, provider *openwrt.Client, state firewallmodule.ServiceState) error {
	for _, item := range []struct {
		packageName string
		desired     []firewallmodule.Section
	}{
		{packageName: "system", desired: state.System},
		{packageName: "stubby", desired: state.Stubby},
		{packageName: "dhcp", desired: state.DHCP},
	} {
		observed, err := provider.UCIGet(ctx, item.packageName)
		if err != nil {
			return err
		}
		if err := firewallmodule.ValidateServicePackage(item.packageName, observed, item.desired); err != nil {
			return err
		}
		changes, diffErr := firewallmodule.DiffOwned(observed, item.desired)
		if diffErr != nil {
			return diffErr
		}
		if len(changes) > 0 {
			return fmt.Errorf("provider %s disabled-state configuration is incomplete", item.packageName)
		}
	}
	return nil
}

func runClientServiceLifecycle(capability, action string, args []string, input io.Reader, out, errOut io.Writer) error {
	allowYes := action == "apply" || action == "teardown" || action == "test"
	allowPlan := action == "plan" || action == "teardown" || action == "test"
	allowCleanup := action == "test"
	options, err := parseClientServiceOptions("module "+capability+" "+action, args, allowYes, allowPlan, allowCleanup)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var lock *site.OperationLock
	if action == "apply" || action == "teardown" || (action == "test" && !options.plan) {
		lock, err = acquireClientServicesLock()
		if err != nil {
			return err
		}
		defer lock.Release()
	}
	serviceContext, err := loadClientServiceContext()
	if err != nil {
		return err
	}
	if action == "status" {
		return runClientServiceStatus(ctx, capability, serviceContext, out)
	}
	if action == "test" {
		return runClientServiceTest(ctx, capability, serviceContext, options, input, out, errOut)
	}
	if action == "plan" {
		return runClientServicePlan(ctx, capability, serviceContext, out)
	}
	provider, err := requireClientProvider(ctx, serviceContext.Site, serviceContext.Desired, serviceContext.Host)
	if err != nil {
		return err
	}
	if action == "teardown" {
		return runClientServiceTeardown(ctx, capability, serviceContext, provider, options, input, out)
	}
	return runClientServiceApply(ctx, capability, serviceContext, provider, options, input, out, errOut)
}

func runClientServicePlan(ctx context.Context, capability string, serviceContext clientServiceContext, out io.Writer) error {
	provider, err := requireClientProvider(ctx, serviceContext.Site, serviceContext.Desired, serviceContext.Host)
	if err != nil {
		return err
	}
	modules, configChanged, err := prepareClientModules(serviceContext.Config.Modules, capability, true, serviceContext.Site)
	if err != nil {
		return err
	}
	state, err := firewallmodule.ServiceStateFromModules(serviceContext.Site, modules)
	if err != nil {
		return err
	}
	composed, err := composeClientAppliance(serviceContext, modules)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "%s plan\n", strings.ToUpper(capability))
	if (capability == "dns" && serviceContext.Config.Modules.DNS == nil) || (capability == "dhcp" && serviceContext.Config.Modules.DHCP == nil) {
		fmt.Fprintf(out, "  Configuration: enable %s and materialise reference defaults\n", capability)
	}
	changes := 0
	for _, item := range []struct {
		packageName string
		sections    []firewallmodule.Section
	}{
		{packageName: "system", sections: state.System},
		{packageName: "stubby", sections: state.Stubby},
		{packageName: "dhcp", sections: state.DHCP},
		{packageName: "firewall", sections: composed.Firewall},
	} {
		current, err := provider.UCIGet(ctx, item.packageName)
		if err != nil {
			return err
		}
		var packageChanges []firewallmodule.Mutation
		var diffErr error
		if item.packageName == "firewall" {
			packageChanges, diffErr = firewallmodule.DiffFirewall(current, item.sections)
		} else {
			packageChanges, diffErr = firewallmodule.DiffOwned(current, item.sections)
		}
		if diffErr != nil {
			return diffErr
		}
		changes += len(packageChanges)
		for _, change := range packageChanges {
			fmt.Fprintf(out, "  %s %s.%s\n", change.Kind, item.packageName, change.Section.Name)
		}
	}
	if !configChanged && changes == 0 {
		if err := verifyClientServices(ctx, provider, state, capability); err == nil {
			fmt.Fprintln(out, "  No changes required; desired state and runtime are ready")
		} else {
			fmt.Fprintf(out, "  Runtime: reconciliation/readiness required (%s)\n", err)
		}
	} else if configChanged {
		fmt.Fprintf(out, "  Configuration: save enabled %s intent\n", capability)
	} else if changes > 0 {
		fmt.Fprintf(out, "  Provider: reconcile %d owned change(s)\n", changes)
	}
	fmt.Fprintln(out, "  No mutation or confirmation prompt")
	return nil
}

func runClientServiceStatus(ctx context.Context, capability string, serviceContext clientServiceContext, out io.Writer) error {
	var configured bool
	if capability == "dns" {
		configured = serviceContext.Config.Modules.DNS != nil && clientservices.Enabled(serviceContext.Config.Modules.DNS.Enabled)
	} else {
		configured = serviceContext.Config.Modules.DHCP != nil && clientservices.Enabled(serviceContext.Config.Modules.DHCP.Enabled)
	}
	if !configured {
		fmt.Fprintf(out, "%s: not configured\n", strings.ToUpper(capability))
		return errors.New(strings.ToLower(capability) + " capability is not configured")
	}
	provider, err := requireClientProvider(ctx, serviceContext.Site, serviceContext.Desired, serviceContext.Host)
	if err != nil {
		fmt.Fprintf(out, "%s: unavailable\nReason: %s\n", strings.ToUpper(capability), err)
		return err
	}
	state, err := firewallmodule.ServiceStateFromModules(serviceContext.Site, serviceContext.Config.Modules)
	if err != nil {
		return err
	}
	if err := verifyClientServices(ctx, provider, state, capability); err != nil {
		pending, pendingErr := benignDHCPAdditions(ctx, provider, state.DHCP)
		if strings.Contains(err.Error(), "not at the desired state") && pendingErr == nil && pending {
			fmt.Fprintf(out, "%s: CHECKING\nReason: additive reservation or DNS record intent is pending provider reconciliation\n", strings.ToUpper(capability))
			return nil
		}
		fmt.Fprintf(out, "%s: FAIL\nReason: %s\n", strings.ToUpper(capability), err)
		return err
	}
	fmt.Fprintf(out, "%s: PASS\nService: native provider configuration and readiness verified\n", strings.ToUpper(capability))
	return nil
}

func prepareClientModules(current clientservices.Modules, capability string, enable bool, serviceSite model.Site) (clientservices.Modules, bool, error) {
	proposed := current.Clone()
	if capability == "dns" {
		if proposed.DNS == nil {
			if !enable {
				return proposed, false, nil
			}
			proposed.DNS = &clientservices.DNSConfig{Enabled: boolPointer(true)}
		} else {
			proposed.DNS.Enabled = boolPointer(enable)
		}
	} else {
		if proposed.DHCP == nil {
			if !enable {
				return proposed, false, nil
			}
			proposed.DHCP = &clientservices.DHCPConfig{Enabled: boolPointer(true)}
		} else {
			proposed.DHCP.Enabled = boolPointer(enable)
		}
	}
	if enable {
		proposed = proposed.Normalize()
		if capability == "dhcp" && (proposed.DNS == nil || !clientservices.Enabled(proposed.DNS.Enabled)) {
			return clientservices.Modules{}, false, errors.New("DHCP requires configured usable DNS; run boetticher module dns apply --yes first")
		}
	}
	if err := clientservices.Validate(proposed, serviceSite); err != nil {
		return clientservices.Modules{}, false, err
	}
	return proposed, !reflect.DeepEqual(current, proposed), nil
}

func runClientServiceApply(ctx context.Context, capability string, serviceContext clientServiceContext, provider *openwrt.Client, options clientServiceOptions, input io.Reader, out, errOut io.Writer) error {
	proposed, configChanged, err := prepareClientModules(serviceContext.Config.Modules, capability, true, serviceContext.Site)
	if err != nil {
		return err
	}
	infrastructureChanged := false
	if proposed.DNS != nil {
		infrastructure, infrastructureErr := firewallmodule.InfrastructureDNSRecords(serviceContext.Site)
		if infrastructureErr != nil {
			return infrastructureErr
		}
		desiredInfrastructure := infrastructureRecordsForModules(infrastructure)
		infrastructureChanged = !reflect.DeepEqual(proposed.DNS.Infrastructure, desiredInfrastructure)
		proposed.DNS.Infrastructure = desiredInfrastructure
	}
	state, err := firewallmodule.ServiceStateFromModules(serviceContext.Site, proposed)
	if err != nil {
		return err
	}
	changes, err := clientServiceChangeCount(ctx, provider, serviceContext, proposed)
	if err != nil {
		return err
	}
	if changes == 0 && !configChanged && !infrastructureChanged {
		if err := verifyClientServices(ctx, provider, state, capability); err != nil {
			return err
		}
		fmt.Fprintf(out, "%s: No changes required.\n", strings.ToUpper(capability))
		return nil
	}
	if !options.yes {
		if input == nil {
			return fmt.Errorf("module %s apply requires --yes or an interactive confirmation", capability)
		}
		answer, promptErr := promptYesNo(bufio.NewReader(input), out, fmt.Sprintf("Apply %s client services and change appliance policy? [y/N]: ", capability), false)
		if promptErr != nil {
			return promptErr
		}
		if !answer {
			return fmt.Errorf("module %s apply cancelled", capability)
		}
	}
	serviceContext.Config.Modules = proposed
	ensureClientNetworkIntent(&serviceContext.Config)
	if err := controllerhost.SaveConfig(serviceContext.Config); err != nil {
		return err
	}
	if _, _, err := reconcileClientServices(ctx, provider, serviceContext, proposed); err != nil {
		fmt.Fprintln(out, "Configuration saved; application failed.")
		return fmt.Errorf("reconcile %s service configuration: %w", capability, err)
	}
	if err := verifyClientServices(ctx, provider, state, capability); err != nil {
		fmt.Fprintln(out, "Configuration saved; application failed.")
		return err
	}
	fmt.Fprintf(out, "%s: PASS\nConfiguration: saved\nService: ready\n", strings.ToUpper(capability))
	_ = errOut
	return nil
}

func infrastructureRecordsForModules(records []model.DNSRecord) []clientservices.DNSRecord {
	result := make([]clientservices.DNSRecord, 0, len(records))
	for _, record := range records {
		result = append(result, clientservices.DNSRecord{Name: record.Name, Type: record.Type, Value: record.Address})
	}
	return result
}

func runClientServiceTeardown(ctx context.Context, capability string, serviceContext clientServiceContext, provider *openwrt.Client, options clientServiceOptions, input io.Reader, out io.Writer) error {
	if serviceContext.Config.Modules.Tailnet != nil && serviceContext.Config.Modules.Tailnet.Enabled && (capability == "dns" || capability == "dhcp") {
		return errors.New("client-service teardown refused while Tailnet is enabled; run module tailnet teardown first")
	}
	if capability == "dns" && serviceContext.Config.Modules.DHCP != nil && clientservices.Enabled(serviceContext.Config.Modules.DHCP.Enabled) {
		return errors.New("DNS teardown refused while DHCP is enabled; run module dhcp teardown first")
	}
	proposed, configChanged, err := prepareClientModules(serviceContext.Config.Modules, capability, false, serviceContext.Site)
	if err != nil {
		return err
	}
	state, err := firewallmodule.ServiceStateFromModules(serviceContext.Site, proposed)
	if err != nil {
		return err
	}
	changes, err := clientServiceChangeCount(ctx, provider, serviceContext, proposed)
	if err != nil {
		return err
	}
	if options.plan {
		fmt.Fprintf(out, "%s teardown\n", strings.ToUpper(capability))
		if configChanged {
			fmt.Fprintf(out, "  Configuration: disable %s and preserve desired records/reservations\n", capability)
		}
		if changes == 0 {
			fmt.Fprintln(out, "  Provider: no owned changes required")
		} else {
			fmt.Fprintf(out, "  Provider: reconcile %d owned change(s)\n", changes)
		}
		fmt.Fprintln(out, "  No mutation or confirmation prompt")
		return nil
	}
	if !configChanged && changes == 0 {
		if err := verifyDisabledClientServices(ctx, provider, state); err != nil {
			return err
		}
		fmt.Fprintf(out, "%s teardown: already disabled/no change\n", strings.ToUpper(capability))
		return nil
	}
	if !options.yes {
		if input == nil {
			return fmt.Errorf("module %s teardown requires --yes or an interactive confirmation", capability)
		}
		answer, promptErr := promptYesNo(bufio.NewReader(input), out, fmt.Sprintf("Disable %s client service? [y/N]: ", capability), false)
		if promptErr != nil {
			return promptErr
		}
		if !answer {
			return fmt.Errorf("module %s teardown cancelled", capability)
		}
	}
	if configChanged {
		serviceContext.Config.Modules = proposed
		ensureClientNetworkIntent(&serviceContext.Config)
		if err := controllerhost.SaveConfig(serviceContext.Config); err != nil {
			return err
		}
	}
	if _, _, err := reconcileClientServices(ctx, provider, serviceContext, proposed); err != nil {
		if configChanged {
			fmt.Fprintln(out, "Configuration saved; application failed.")
		}
		return err
	}
	if err := verifyDisabledClientServices(ctx, provider, state); err != nil {
		return err
	}
	fmt.Fprintf(out, "%s teardown: PASS\n", strings.ToUpper(capability))
	return nil
}

func runClientServiceTest(ctx context.Context, capability string, serviceContext clientServiceContext, options clientServiceOptions, input io.Reader, out, errOut io.Writer) (returnErr error) {
	if options.plan {
		renderClientServiceTestPlan(out, capability, serviceContext)
		return nil
	}
	if options.cleanupOnly {
		return cleanupClientServiceTest(ctx, serviceContext, out)
	}
	if !options.yes {
		if input == nil {
			return fmt.Errorf("module %s test requires --yes or an interactive confirmation", capability)
		}
		answer, promptErr := promptYesNo(bufio.NewReader(input), out, fmt.Sprintf("Run the bounded %s client-service test? [y/N]: ", capability), false)
		if promptErr != nil {
			return promptErr
		}
		if !answer {
			return fmt.Errorf("module %s test cancelled", capability)
		}
	}
	provider, err := requireClientProvider(ctx, serviceContext.Site, serviceContext.Desired, serviceContext.Host)
	if err != nil {
		return err
	}
	state, err := firewallmodule.ServiceStateFromModules(serviceContext.Site, serviceContext.Config.Modules)
	if err != nil {
		return err
	}
	if err := verifyClientServices(ctx, provider, state, capability); err != nil {
		return err
	}
	originalModules := serviceContext.Config.Modules.Clone()
	proposedModules := originalModules
	temporaryIntent := false
	if capability == "dhcp" {
		proposedModules, err = prepareTestDHCPModules(ctx, serviceContext, provider)
		if err != nil {
			return err
		}
		temporaryIntent = !reflect.DeepEqual(originalModules, proposedModules)
		if temporaryIntent {
			defer func() {
				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 45*time.Second)
				if cleanupErr := restoreClientServiceTestIntent(cleanupCtx, serviceContext, originalModules, provider); cleanupErr != nil {
					returnErr = errors.Join(returnErr, cleanupErr)
					if errOut != nil {
						fmt.Fprintf(errOut, "client-service test cleanup failed: %s\n", cleanupErr)
					}
				}
				cleanupCancel()
			}()
			serviceContext.Config.Modules = proposedModules
			ensureClientNetworkIntent(&serviceContext.Config)
			if err := controllerhost.SaveConfig(serviceContext.Config); err != nil {
				return err
			}
			if _, _, err := reconcileClientServices(ctx, provider, serviceContext, proposedModules); err != nil {
				return fmt.Errorf("apply test-owned DHCP identities: %w", err)
			}
			state, err = firewallmodule.ServiceStateFromModules(serviceContext.Site, proposedModules)
			if err != nil {
				return err
			}
			if err := verifyClientServices(ctx, provider, state, capability); err != nil {
				return err
			}
		}
	}
	zones, err := clientServiceTestZones(serviceContext, proposedModules, capability)
	if err != nil {
		return err
	}
	queries, err := clientServiceDNSQueries(serviceContext.Config.Modules, labConfigDomain(serviceContext.Config))
	if err != nil {
		return err
	}
	request := firewalltest.Request{Version: firewalltest.ProtocolVersion, Action: "client-services", Service: capability, Domain: labConfigDomain(serviceContext.Config), UseDHCP: capability == "dhcp", Zones: zones, DNSQueries: queries}
	response, helperErr := invokeFirewallTestHost(ctx, serviceContext.Host, request)
	if helperErr != nil || !response.OK || !response.CleanupOK {
		return fmt.Errorf("%s client-service test failed: %s", capability, helperResponseDetail(response, helperErr))
	}
	for _, result := range firewalltest.SortedResults(response.Results) {
		fmt.Fprintf(out, "%s %s: %s (%s)\n", result.Group, result.Name, result.Status, result.Detail)
	}
	fmt.Fprintf(out, "%s test: PASS\nTemporary client fixtures cleaned\n", strings.ToUpper(capability))
	_ = errOut
	return nil
}

func renderClientServiceTestPlan(out io.Writer, capability string, serviceContext clientServiceContext) {
	fmt.Fprintf(out, "%s test plan\n", strings.ToUpper(capability))
	normalized := serviceContext.Config.Modules.Normalize()
	for _, zone := range serviceContext.Site.Network.Zones {
		fmt.Fprintf(out, "  %s: namespace=%s veth=%s vlan=%d subnet=%s gateway=%s", zone.Name, firewalltest.NamespaceName(zone.Name), firewalltest.FixtureName(zone.Name)+"-h", zone.VLAN, zone.Network, zone.Gateway)
		if capability == "dhcp" {
			scope := "configured scope"
			if normalized.DHCP == nil || !clientservices.Enabled(normalized.DHCP.Enabled) {
				scope = "requires enabled DHCP"
			} else {
				for _, candidate := range normalized.DHCP.Scopes {
					if strings.EqualFold(candidate.Zone, zone.Name) {
						scope = candidate.Mode
						if candidate.Mode == clientservices.ScopePool {
							scope += " " + candidate.PoolStart + "-" + candidate.PoolEnd
						} else {
							scope += " test identity from .200-.249"
						}
						break
					}
				}
			}
			fmt.Fprintf(out, " dhcp=%s", scope)
		} else {
			fmt.Fprint(out, " static routed DNS fixture address candidate .250-.254")
		}
		fmt.Fprintln(out)
	}
	fmt.Fprintln(out, "  expected: exact service options, local/public DNS answers, and bounded cleanup")
	fmt.Fprintln(out, "  No namespaces, listeners, clients, provider state, or configuration are created")
}

const testIdentityPrefix = "boetticher-test-"

func clientServiceTestZones(serviceContext clientServiceContext, modules clientservices.Modules, capability string) ([]firewalltest.Zone, error) {
	normalized := modules.Normalize()
	scopes := map[string]clientservices.DHCPScope{}
	if normalized.DHCP != nil {
		for _, scope := range normalized.DHCP.Scopes {
			scopes[strings.ToUpper(scope.Zone)] = scope
		}
	}
	reservations := map[string][]clientservices.Reservation{}
	if normalized.DHCP != nil {
		for _, reservation := range normalized.DHCP.Reservations {
			if strings.HasPrefix(strings.ToLower(reservation.Name), testIdentityPrefix) {
				reservations[strings.ToUpper(reservation.Zone)] = append(reservations[strings.ToUpper(reservation.Zone)], reservation)
			}
		}
	}
	zones := make([]firewalltest.Zone, 0, len(serviceContext.Site.Network.Zones))
	for _, zone := range serviceContext.Site.Network.Zones {
		fixture := firewalltest.Zone{Name: zone.Name, Type: string(zone.Type), VLAN: zone.VLAN, Subnet: zone.Network, Gateway: zone.Gateway}
		if capability != "dhcp" {
			zones = append(zones, fixture)
			continue
		}
		scope := scopes[strings.ToUpper(zone.Name)]
		fixture.DHCPMode = scope.Mode
		fixture.PoolStart, fixture.PoolEnd = scope.PoolStart, scope.PoolEnd
		if scope.Mode == clientservices.ScopeReservationsOnly {
			entries := reservations[strings.ToUpper(zone.Name)]
			if len(entries) == 0 {
				return nil, fmt.Errorf("reservation-only scope %s has no test-owned reserved client for a positive control", zone.Name)
			}
			reservation := entries[0]
			fixture.Address, fixture.ClientMAC, fixture.ExpectedName = reservation.Address, reservation.MAC, reservation.Name
			fixture.UnknownClientMAC = testUnknownMAC(zone.Name)
		}
		zones = append(zones, fixture)
	}
	return zones, nil
}

func prepareTestDHCPModules(ctx context.Context, serviceContext clientServiceContext, provider *openwrt.Client) (clientservices.Modules, error) {
	if serviceContext.Config.Modules.DHCP == nil || !clientservices.Enabled(serviceContext.Config.Modules.DHCP.Enabled) {
		return clientservices.Modules{}, errors.New("DHCP capability is not configured; run boetticher module dhcp apply --yes first")
	}
	observed, err := provider.UCIGet(ctx, "dhcp")
	if err != nil {
		return clientservices.Modules{}, err
	}
	proposed := serviceContext.Config.Modules.Normalize().Clone()
	if err := firewallmodule.ValidateServicePackage("dhcp", observed, nil); err != nil {
		return clientservices.Modules{}, err
	}
	usedAddresses := map[string]struct{}{}
	usedMACs := map[string]struct{}{}
	usedNames := map[string]struct{}{}
	for _, reservation := range proposed.DHCP.Reservations {
		usedAddresses[reservation.Address] = struct{}{}
		if mac, macErr := clientservices.CanonicalMAC(reservation.MAC); macErr == nil {
			usedMACs[mac] = struct{}{}
		}
		usedNames[strings.ToLower(reservation.Name)] = struct{}{}
	}
	for _, component := range serviceContext.Site.PlatformComponents() {
		if component.Address != "" {
			usedAddresses[component.Address] = struct{}{}
		}
		if component.MAC != "" {
			if mac, macErr := clientservices.CanonicalMAC(component.MAC); macErr == nil {
				usedMACs[mac] = struct{}{}
			}
		}
		if component.Hostname != "" {
			usedNames[strings.ToLower(component.Hostname)] = struct{}{}
		}
	}
	for name, section := range observed {
		if section.Type != "host" {
			continue
		}
		if address := section.Options["ip"]; address != "" {
			usedAddresses[address] = struct{}{}
		}
		if mac := section.Options["mac"]; mac != "" {
			if canonical, macErr := clientservices.CanonicalMAC(mac); macErr == nil {
				usedMACs[canonical] = struct{}{}
			}
		}
		usedNames[strings.ToLower(name)] = struct{}{}
	}
	leases, err := readNativeDHCPLeases(ctx, serviceContext.Host)
	if err != nil && !errors.Is(err, errLeaseFileAbsent) {
		return clientservices.Modules{}, err
	}
	now := time.Now().Unix()
	for _, lease := range leases {
		if lease.Expiry != 0 && lease.Expiry <= now {
			continue
		}
		usedAddresses[lease.Address] = struct{}{}
		usedMACs[lease.MAC] = struct{}{}
	}
	for index, zone := range serviceContext.Site.Network.Zones {
		mode := ""
		for _, scope := range proposed.DHCP.Scopes {
			if strings.EqualFold(scope.Zone, zone.Name) {
				mode = scope.Mode
				break
			}
		}
		if mode != clientservices.ScopeReservationsOnly {
			continue
		}
		address, err := nextTestAddress(zone, usedAddresses)
		if err != nil {
			return clientservices.Modules{}, err
		}
		mac := nextTestMAC(index, usedMACs)
		if mac == "" {
			return clientservices.Modules{}, errors.New("no collision-free test client MAC remains")
		}
		name := testIdentityPrefix + strings.ToLower(zone.Name)
		for {
			if _, exists := usedNames[name]; !exists {
				break
			}
			name += "-x"
		}
		proposed.DHCP.Reservations = append(proposed.DHCP.Reservations, clientservices.Reservation{Name: name, Zone: zone.Name, MAC: mac, Address: address})
		usedAddresses[address] = struct{}{}
		usedMACs[mac] = struct{}{}
		unknownMAC := testUnknownMAC(zone.Name)
		for {
			if _, exists := usedMACs[unknownMAC]; !exists {
				break
			}
			parsed := strings.Split(unknownMAC, ":")
			last, parseErr := strconv.ParseUint(parsed[len(parsed)-1], 16, 8)
			if parseErr != nil {
				return clientservices.Modules{}, errors.New("test unknown-client MAC is malformed")
			}
			parsed[len(parsed)-1] = fmt.Sprintf("%02x", (last+1)&0xff)
			unknownMAC = strings.Join(parsed, ":")
		}
		usedMACs[unknownMAC] = struct{}{}
		usedNames[name] = struct{}{}
	}
	if err := clientservices.Validate(proposed, serviceContext.Site); err != nil {
		return clientservices.Modules{}, err
	}
	return proposed, nil
}

type nativeDHCPLease struct {
	Expiry   int64
	MAC      string
	Address  string
	Hostname string
	ClientID string
}

func tailnetLeaseConflict(reservation clientservices.Reservation, leases []nativeDHCPLease, now int64) error {
	wantMAC := strings.ToLower(strings.TrimSpace(reservation.MAC))
	wantName := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(reservation.Name), "."))
	for _, lease := range leases {
		if lease.Expiry != 0 && lease.Expiry <= now {
			continue
		}
		leaseMAC := strings.ToLower(strings.TrimSpace(lease.MAC))
		leaseName := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(lease.Hostname), "."))
		if lease.Address == reservation.Address && leaseMAC != wantMAC {
			return fmt.Errorf("active DHCP lease holds Tailnet address %s for MAC %s", reservation.Address, lease.MAC)
		}
		if leaseMAC == wantMAC && lease.Address != reservation.Address {
			return fmt.Errorf("Tailnet MAC %s has an active DHCP lease at %s", reservation.MAC, lease.Address)
		}
		if leaseName != "" && leaseName == wantName && (leaseMAC != wantMAC || lease.Address != reservation.Address) {
			return fmt.Errorf("Tailnet hostname %s has an active DHCP lease for another identity", reservation.Name)
		}
	}
	return nil
}

var errLeaseFileAbsent = errors.New("native DHCP lease file is absent")

func readNativeDHCPLeases(ctx context.Context, host firewallmodule.HostClient) ([]nativeDHCPLease, error) {
	result, err := host.Run(ctx, "set -eu; qm guest exec "+fmt.Sprint(firewallmodule.ProviderVMID)+" --synchronous 1 -- /bin/cat "+clientservices.LeaseFilePath)
	if err != nil {
		return nil, err
	}
	var response struct {
		ExitCode int    `json:"exitcode"`
		Data     string `json:"out-data"`
		Error    string `json:"err-data"`
	}
	if err := json.Unmarshal(result.Stdout, &response); err != nil {
		return nil, errors.New("provider guest agent returned malformed DHCP lease state")
	}
	if response.ExitCode != 0 {
		if strings.Contains(strings.ToLower(response.Error), "no such file") {
			return nil, errLeaseFileAbsent
		}
		return nil, fmt.Errorf("read native DHCP leases failed (%d): %s", response.ExitCode, strings.TrimSpace(response.Error))
	}
	return parseNativeDHCPLeaseLines(response.Data)
}

func parseNativeDHCPLeaseLines(data string) ([]nativeDHCPLease, error) {
	leases := []nativeDHCPLease{}
	for _, line := range strings.Split(strings.TrimSpace(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			return nil, errors.New("provider DHCP lease state contains a malformed entry")
		}
		expiry, parseErr := strconv.ParseInt(fields[0], 10, 64)
		mac, macErr := clientservices.CanonicalMAC(fields[1])
		address, addressErr := netip.ParseAddr(fields[2])
		if parseErr != nil || macErr != nil || addressErr != nil || !address.Is4() {
			return nil, errors.New("provider DHCP lease state contains a malformed entry")
		}
		hostname, clientID := "", ""
		if len(fields) >= 4 && fields[3] != "*" {
			hostname = fields[3]
		}
		if len(fields) >= 5 && fields[4] != "*" {
			clientID = fields[4]
		}
		leases = append(leases, nativeDHCPLease{Expiry: expiry, MAC: mac, Address: address.String(), Hostname: hostname, ClientID: clientID})
	}
	return leases, nil
}

func nextTestAddress(zone model.Zone, used map[string]struct{}) (string, error) {
	prefix, err := netip.ParsePrefix(zone.Network)
	if err != nil {
		return "", fmt.Errorf("parse %s subnet: %w", zone.Name, err)
	}
	base := prefix.Masked().Addr().As4()
	for octet := 200; octet < clientservices.ProbeAddressStart; octet++ {
		candidate := base
		candidate[3] = uint8(octet)
		address := netip.AddrFrom4(candidate).String()
		if address == zone.Gateway || address == prefix.Addr().String() {
			continue
		}
		if _, exists := used[address]; !exists {
			return address, nil
		}
	}
	return "", fmt.Errorf("no collision-free test reservation address remains in %s", zone.Name)
}

func nextTestMAC(index int, used map[string]struct{}) string {
	for offset := 0; offset < 256; offset++ {
		candidate := fmt.Sprintf("02:00:00:4b:4a:%02x", (index+offset)&0xff)
		if _, exists := used[candidate]; !exists {
			return candidate
		}
	}
	return ""
}

func testUnknownMAC(zone string) string {
	checksum := 0
	for _, character := range zone {
		checksum += int(character)
	}
	return fmt.Sprintf("02:00:00:4b:4b:%02x", checksum&0xff)
}

func restoreClientServiceTestIntent(ctx context.Context, serviceContext clientServiceContext, original clientservices.Modules, provider *openwrt.Client) error {
	serviceContext.Config.Modules = original
	ensureClientNetworkIntent(&serviceContext.Config)
	if err := controllerhost.SaveConfig(serviceContext.Config); err != nil {
		return err
	}
	_, _, err := reconcileClientServices(ctx, provider, serviceContext, original)
	return err
}

func cleanupClientServiceTest(ctx context.Context, serviceContext clientServiceContext, out io.Writer) error {
	response, helperErr := invokeFirewallTestHost(ctx, serviceContext.Host, firewalltest.Request{Version: firewalltest.ProtocolVersion, Action: "cleanup"})
	if helperErr != nil || !response.OK || !response.CleanupOK {
		return fmt.Errorf("client-service fixture cleanup failed: %s", helperResponseDetail(response, helperErr))
	}
	config := serviceContext.Config
	changed := false
	if config.Modules.DHCP != nil {
		kept := config.Modules.DHCP.Reservations[:0]
		for _, reservation := range config.Modules.DHCP.Reservations {
			if strings.HasPrefix(strings.ToLower(reservation.Name), testIdentityPrefix) {
				changed = true
				continue
			}
			kept = append(kept, reservation)
		}
		config.Modules.DHCP.Reservations = kept
	}
	if config.Modules.DNS != nil {
		kept := config.Modules.DNS.Records[:0]
		for _, record := range config.Modules.DNS.Records {
			if strings.HasPrefix(strings.ToLower(record.Name), testIdentityPrefix) {
				changed = true
				continue
			}
			kept = append(kept, record)
		}
		config.Modules.DNS.Records = kept
	}
	if changed {
		if err := controllerhost.SaveConfig(config); err != nil {
			return err
		}
		fmt.Fprintln(out, "Removed recognised test-owned client-service intent")
		status, inspectErr := firewallmodule.InspectHostProvider(ctx, serviceContext.Host)
		if inspectErr != nil {
			return fmt.Errorf("test-owned client intent removed but provider ownership could not be checked: %w", inspectErr)
		}
		if status.Exists {
			provider, providerErr := requireClientProvider(ctx, serviceContext.Site, serviceContext.Desired, serviceContext.Host)
			if providerErr != nil {
				return fmt.Errorf("test-owned client intent removed; provider cleanup is pending: %w", providerErr)
			}
			if _, _, reconcileErr := reconcileClientServices(ctx, provider, serviceContext, config.Modules); reconcileErr != nil {
				return fmt.Errorf("remove test-owned provider client state: %w", reconcileErr)
			}
		}
	}
	if !changed {
		fmt.Fprintln(out, "Client-service test cleanup: already clean")
	} else {
		fmt.Fprintln(out, "Client-service test cleanup: PASS")
	}
	return nil
}

func clientServiceDNSQueries(modules clientservices.Modules, domain string) ([]firewalltest.DNSQuery, error) {
	queries := []firewalltest.DNSQuery{{Name: firewalltest.PublicHost, Type: "A"}}
	if modules.DNS == nil || !clientservices.Enabled(modules.DNS.Enabled) {
		return nil, errors.New("DNS test requires enabled DNS capability")
	}
	for _, record := range modules.DNS.Records {
		name, err := clientservices.CanonicalName(record.Name, domain)
		if err != nil {
			return nil, err
		}
		switch record.Type {
		case "A":
			queries = append(queries, firewalltest.DNSQuery{Name: name, Type: "A", Expected: record.Value})
			queries = append(queries, firewalltest.DNSQuery{Name: reverseName(record.Value), Type: "PTR", Expected: name})
		case "CNAME":
			target, targetErr := clientservices.CanonicalName(record.Value, domain)
			if targetErr != nil {
				return nil, targetErr
			}
			queries = append(queries, firewalltest.DNSQuery{Name: name, Type: "CNAME", Expected: target})
		}
	}
	if modules.DHCP != nil && clientservices.Enabled(modules.DHCP.Enabled) {
		for _, reservation := range modules.DHCP.Reservations {
			if !strings.HasPrefix(strings.ToLower(reservation.Name), testIdentityPrefix) {
				continue
			}
			name, nameErr := clientservices.CanonicalName(reservation.Name, domain)
			if nameErr != nil {
				return nil, nameErr
			}
			queries = append(queries, firewalltest.DNSQuery{Name: name, Type: "A", Expected: reservation.Address})
			queries = append(queries, firewalltest.DNSQuery{Name: reverseName(reservation.Address), Type: "PTR", Expected: name})
		}
	}
	queries = append(queries, firewalltest.DNSQuery{Name: "does-not-exist." + strings.TrimSuffix(domain, "."), Type: "A", ExpectNoAnswer: true})
	return queries, nil
}

func reverseName(value string) string {
	address := net.ParseIP(value).To4()
	if address == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", address[3], address[2], address[1], address[0])
}

func displayLeaseValue(value string) string {
	if value == "" {
		return "<not supplied>"
	}
	return value
}

func boolPointer(value bool) *bool { return &value }

func clientCapabilityIntentLabel(value any) string {
	switch config := value.(type) {
	case *clientservices.DNSConfig:
		if config == nil {
			return "not configured"
		}
		if !clientservices.Enabled(config.Enabled) {
			return "disabled"
		}
		return "enabled"
	case *clientservices.DHCPConfig:
		if config == nil {
			return "not configured"
		}
		if !clientservices.Enabled(config.Enabled) {
			return "disabled"
		}
		return "enabled"
	default:
		return "not configured"
	}
}

func runDHCPListReservations(args []string, out io.Writer) error {
	if len(args) != 0 {
		return errors.New("usage: boetticher module dhcp list-reservations")
	}
	config, err := controllerhost.LoadConfig()
	if err != nil {
		return err
	}
	if config.Modules.DHCP == nil {
		fmt.Fprintln(out, "DHCP: not configured")
		return nil
	}
	reservations := append([]clientservices.Reservation(nil), config.Modules.DHCP.Reservations...)
	sort.Slice(reservations, func(i, j int) bool { return reservations[i].Name < reservations[j].Name })
	for _, reservation := range reservations {
		fmt.Fprintf(out, "%s.%s %s %s %s\n", reservation.Name, labConfigDomain(config), reservation.Zone, reservation.Address, reservation.MAC)
	}
	return nil
}

func runDHCPListLeases(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("module dhcp list-leases", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	details := fs.Bool("details", false, "include client identifiers")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return errors.New("usage: boetticher module dhcp list-leases [--details]")
	}
	serviceContext, err := loadClientServiceContext()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if serviceContext.Config.Modules.DHCP == nil || !clientservices.Enabled(serviceContext.Config.Modules.DHCP.Enabled) {
		return errors.New("DHCP capability is not configured")
	}
	if _, err := requireClientProvider(ctx, serviceContext.Site, serviceContext.Desired, serviceContext.Host); err != nil {
		return err
	}
	leases, err := readNativeDHCPLeases(ctx, serviceContext.Host)
	if errors.Is(err, errLeaseFileAbsent) {
		fmt.Fprintln(out, "DHCP leases: none")
		return nil
	}
	if err != nil {
		return err
	}
	if len(leases) == 0 {
		fmt.Fprintln(out, "DHCP leases: none")
		return nil
	}
	for _, lease := range leases {
		state := "infinite"
		expires := "infinite"
		if lease.Expiry > 0 {
			expires = time.Unix(lease.Expiry, 0).UTC().Format(time.RFC3339)
			state = "active"
			if lease.Expiry <= time.Now().Unix() {
				state = "expired"
			}
		} else if lease.Expiry < 0 {
			state, expires = "unknown", "unknown"
		}
		fmt.Fprintf(out, "address=%s mac=%s hostname=%s state=%s expires=%s", lease.Address, lease.MAC, displayLeaseValue(lease.Hostname), state, expires)
		if *details {
			fmt.Fprintf(out, " client_id=%s", displayLeaseValue(lease.ClientID))
		}
		fmt.Fprintln(out)
	}
	return nil
}

func runDHCPAddReservation(args []string, input io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher module dhcp add-reservation NAME --zone ZONE --mac MAC --address IPv4 [--yes]")
	}
	name := args[0]
	fs := flag.NewFlagSet("module dhcp add-reservation", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	zone := fs.String("zone", "", "reference LAB zone")
	mac := fs.String("mac", "", "stable Ethernet MAC")
	address := fs.String("address", "", "reserved IPv4 address")
	yes := fs.Bool("yes", false, "approve the desired and provider change")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		return errors.New("usage: boetticher module dhcp add-reservation NAME --zone ZONE --mac MAC --address IPv4 [--yes]")
	}
	lock, err := acquireClientServicesLock()
	if err != nil {
		return err
	}
	defer lock.Release()
	serviceContext, err := loadClientServiceContext()
	if err != nil {
		return err
	}
	if serviceContext.Config.Modules.DHCP == nil || !clientservices.Enabled(serviceContext.Config.Modules.DHCP.Enabled) {
		return errors.New("DHCP capability is not configured; run boetticher module dhcp apply --yes first")
	}
	canonicalMAC, err := clientservices.CanonicalMAC(*mac)
	if err != nil {
		return err
	}
	parsedAddress := net.ParseIP(strings.TrimSpace(*address))
	if parsedAddress == nil || parsedAddress.To4() == nil {
		return errors.New("reservation address must be a canonical IPv4 address")
	}
	reservation := clientservices.Reservation{Name: strings.ToLower(strings.TrimSpace(name)), Zone: strings.ToUpper(strings.TrimSpace(*zone)), MAC: canonicalMAC, Address: parsedAddress.To4().String()}
	identical := false
	for _, existing := range serviceContext.Config.Modules.DHCP.Reservations {
		if strings.EqualFold(existing.Name, reservation.Name) {
			if strings.EqualFold(existing.Zone, reservation.Zone) && existing.Address == reservation.Address && strings.EqualFold(existing.MAC, reservation.MAC) {
				identical = true
				break
			}
			return fmt.Errorf("DHCP reservation %s already exists with a conflicting definition", reservation.Name)
		}
	}
	if !identical {
		serviceContext.Config.Modules.DHCP.Reservations = append(serviceContext.Config.Modules.DHCP.Reservations, reservation)
	}
	if err := clientservices.Validate(serviceContext.Config.Modules, serviceContext.Site); err != nil {
		return err
	}
	return applyClientResourceMutation(serviceContext, "DHCP reservation "+reservation.Name, "dhcp", *yes, input, out, !identical)
}

func runDHCPRemoveReservation(args []string, input io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher module dhcp remove-reservation NAME [--yes]")
	}
	name := strings.ToLower(strings.TrimSpace(args[0]))
	fs := flag.NewFlagSet("module dhcp remove-reservation", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	yes := fs.Bool("yes", false, "approve the desired and provider change")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		return errors.New("usage: boetticher module dhcp remove-reservation NAME [--yes]")
	}
	lock, err := acquireClientServicesLock()
	if err != nil {
		return err
	}
	defer lock.Release()
	serviceContext, err := loadClientServiceContext()
	if err != nil {
		return err
	}
	if serviceContext.Config.Modules.DHCP == nil || !clientservices.Enabled(serviceContext.Config.Modules.DHCP.Enabled) {
		return errors.New("DHCP capability is not configured")
	}
	index := -1
	for i, reservation := range serviceContext.Config.Modules.DHCP.Reservations {
		if strings.EqualFold(reservation.Name, name) {
			index = i
			break
		}
	}
	if index < 0 {
		return fmt.Errorf("no DHCP reservation named %s", name)
	}
	if serviceContext.Config.Modules.Tailnet != nil && serviceContext.Config.Modules.Tailnet.Enabled {
		for _, reservation := range serviceContext.Config.Modules.DHCP.Reservations {
			if strings.EqualFold(reservation.Name, name) && reservation == tailnetReservation() {
				return errors.New("Tailnet reservation cannot be removed while Tailnet is enabled; run module tailnet teardown first")
			}
		}
	}
	serviceContext.Config.Modules.DHCP.Reservations = append(serviceContext.Config.Modules.DHCP.Reservations[:index], serviceContext.Config.Modules.DHCP.Reservations[index+1:]...)
	return applyClientResourceMutation(serviceContext, "remove DHCP reservation "+name, "dhcp", *yes, input, out, true)
}

func runDNSListRecords(args []string, out io.Writer) error {
	if len(args) != 0 {
		return errors.New("usage: boetticher module dns list-records")
	}
	config, err := controllerhost.LoadConfig()
	if err != nil {
		return err
	}
	if config.Modules.DNS == nil {
		fmt.Fprintln(out, "DNS: not configured")
		return nil
	}
	records := append([]clientservices.DNSRecord(nil), config.Modules.DNS.Records...)
	sort.Slice(records, func(i, j int) bool { return records[i].Name < records[j].Name })
	for _, record := range records {
		name, _ := clientservices.CanonicalName(record.Name, labConfigDomain(config))
		fmt.Fprintf(out, "%s %s %s\n", name, record.Type, record.Value)
	}
	return nil
}

func runDNSAddRecord(args []string, input io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher module dns add-record NAME --type A|CNAME --value VALUE [--yes]")
	}
	name := args[0]
	fs := flag.NewFlagSet("module dns add-record", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	recordType := fs.String("type", "", "A or CNAME")
	value := fs.String("value", "", "record value")
	yes := fs.Bool("yes", false, "approve the desired and provider change")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		return errors.New("usage: boetticher module dns add-record NAME --type A|CNAME --value VALUE [--yes]")
	}
	lock, err := acquireClientServicesLock()
	if err != nil {
		return err
	}
	defer lock.Release()
	serviceContext, err := loadClientServiceContext()
	if err != nil {
		return err
	}
	if serviceContext.Config.Modules.DNS == nil || !clientservices.Enabled(serviceContext.Config.Modules.DNS.Enabled) {
		return errors.New("DNS capability is not configured; run boetticher module dns apply --yes first")
	}
	record := clientservices.DNSRecord{Name: strings.ToLower(strings.TrimSpace(name)), Type: strings.ToUpper(strings.TrimSpace(*recordType)), Value: strings.ToLower(strings.TrimSuffix(strings.TrimSpace(*value), "."))}
	if record.Type == "A" {
		ip := net.ParseIP(record.Value)
		if ip == nil || ip.To4() == nil || ip.To4().String() != record.Value {
			return errors.New("A record value must be a canonical IPv4 address")
		}
	} else if record.Type == "CNAME" {
		target, targetErr := clientservices.CanonicalName(record.Value, labConfigDomain(serviceContext.Config))
		if targetErr != nil {
			return targetErr
		}
		record.Value = target
	}
	canonical, err := clientservices.CanonicalName(record.Name, labConfigDomain(serviceContext.Config))
	if err != nil {
		return err
	}
	record.Name = canonical
	identical := false
	for _, existing := range serviceContext.Config.Modules.DNS.Records {
		existingName, _ := clientservices.CanonicalName(existing.Name, labConfigDomain(serviceContext.Config))
		if existingName == canonical {
			if existing.Type == record.Type && existing.Value == record.Value {
				identical = true
				break
			}
			return fmt.Errorf("DNS record %s already exists with a conflicting definition", canonical)
		}
	}
	if !identical {
		serviceContext.Config.Modules.DNS.Records = append(serviceContext.Config.Modules.DNS.Records, record)
	}
	if err := clientservices.Validate(serviceContext.Config.Modules, serviceContext.Site); err != nil {
		return err
	}
	return applyClientResourceMutation(serviceContext, "DNS record "+canonical, "dns", *yes, input, out, !identical)
}

func runDNSRemoveRecord(args []string, input io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher module dns remove-record NAME [--yes]")
	}
	name := args[0]
	fs := flag.NewFlagSet("module dns remove-record", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	yes := fs.Bool("yes", false, "approve the desired and provider change")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		return errors.New("usage: boetticher module dns remove-record NAME [--yes]")
	}
	lock, err := acquireClientServicesLock()
	if err != nil {
		return err
	}
	defer lock.Release()
	serviceContext, err := loadClientServiceContext()
	if err != nil {
		return err
	}
	if serviceContext.Config.Modules.DNS == nil || !clientservices.Enabled(serviceContext.Config.Modules.DNS.Enabled) {
		return errors.New("DNS capability is not configured")
	}
	canonical, err := clientservices.CanonicalName(name, labConfigDomain(serviceContext.Config))
	if err != nil {
		return err
	}
	index := -1
	for i, record := range serviceContext.Config.Modules.DNS.Records {
		existingName, _ := clientservices.CanonicalName(record.Name, labConfigDomain(serviceContext.Config))
		if existingName == canonical {
			index = i
			break
		}
	}
	if index < 0 {
		return fmt.Errorf("no DNS record named %s", canonical)
	}
	serviceContext.Config.Modules.DNS.Records = append(serviceContext.Config.Modules.DNS.Records[:index], serviceContext.Config.Modules.DNS.Records[index+1:]...)
	return applyClientResourceMutation(serviceContext, "remove DNS record "+canonical, "dns", *yes, input, out, true)
}

func applyClientResourceMutation(serviceContext clientServiceContext, description, capability string, yes bool, input io.Reader, out io.Writer, configChanged bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	provider, err := requireClientProvider(ctx, serviceContext.Site, serviceContext.Desired, serviceContext.Host)
	if err != nil {
		return err
	}
	changes, err := clientServiceChangeCount(ctx, provider, serviceContext, serviceContext.Config.Modules)
	if err != nil {
		return err
	}
	if changes == 0 && !configChanged {
		state, stateErr := firewallmodule.ServiceStateFromModules(serviceContext.Site, serviceContext.Config.Modules)
		if stateErr != nil {
			return stateErr
		}
		if err := verifyClientServices(ctx, provider, state, capability); err != nil {
			return err
		}
		fmt.Fprintf(out, "%s: No changes required.\n", description)
		return nil
	}
	if !yes {
		if input == nil {
			return errors.New("mutation requires --yes or an interactive confirmation")
		}
		answer, promptErr := promptYesNo(bufio.NewReader(input), out, "Apply "+description+"? [y/N]: ", false)
		if promptErr != nil {
			return promptErr
		}
		if !answer {
			return errors.New("operation cancelled")
		}
	}
	ensureClientNetworkIntent(&serviceContext.Config)
	if configChanged {
		ensureClientNetworkIntent(&serviceContext.Config)
		if err := controllerhost.SaveConfig(serviceContext.Config); err != nil {
			return err
		}
	}
	if _, _, err := reconcileClientServices(ctx, provider, serviceContext, serviceContext.Config.Modules); err != nil {
		if configChanged {
			fmt.Fprintln(out, "Configuration saved; application failed.")
		}
		return err
	}
	fmt.Fprintf(out, "%s: PASS\n", description)
	return nil
}

func ensureClientNetworkIntent(config *controllerhost.LabConfig) {
	if config.Network == nil {
		want := controllerhost.DefaultNetworkConfig()
		config.Network = &want
	}
	if config.Network.Domain == "" {
		config.Network.Domain = model.DefaultDomain
	}
}

func labConfigDomain(config controllerhost.LabConfig) string {
	if config.Network != nil && config.Network.Domain != "" {
		return config.Network.Domain
	}
	return model.DefaultDomain
}
