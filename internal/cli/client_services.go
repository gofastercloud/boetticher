package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"sort"
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
	yes  bool
	plan bool
}

func parseClientServiceOptions(command string, args []string, allowYes, allowPlan bool) (clientServiceOptions, error) {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	options := clientServiceOptions{}
	if allowYes {
		fs.BoolVar(&options.yes, "yes", false, "approve the capability change")
	}
	if allowPlan {
		fs.BoolVar(&options.plan, "plan", false, "preview the capability change")
	}
	if err := fs.Parse(args); err != nil {
		return clientServiceOptions{}, err
	}
	if fs.NArg() != 0 {
		return clientServiceOptions{}, fmt.Errorf("usage: boetticher module %s %s", strings.TrimPrefix(command, "module "), serviceUsageSuffix(allowYes, allowPlan))
	}
	if options.plan && options.yes {
		return clientServiceOptions{}, errors.New("--plan cannot be combined with --yes")
	}
	return options, nil
}

func serviceUsageSuffix(allowYes, allowPlan bool) string {
	parts := []string{}
	if allowPlan {
		parts = append(parts, "--plan")
	}
	if allowYes {
		parts = append(parts, "--yes")
	}
	if len(parts) == 0 {
		return ""
	}
	return "[" + strings.Join(parts, "|") + "]"
}

type clientServiceContext struct {
	Config  controllerhost.LabConfig
	Site    model.Site
	Desired firewallmodule.DesiredState
	Host    firewallmodule.HostClient
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
	return clientServiceContext{Config: config, Site: current, Desired: desired, Host: host}, nil
}

func acquireClientServicesLock() (*site.OperationLock, error) {
	return site.AcquireOperationLockAt(controllerhost.ClientServicesLockPath)
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
	return provider, nil
}

func reconcileClientServices(ctx context.Context, provider *openwrt.Client, current model.Site, modules clientservices.Modules) (firewallmodule.ServiceState, int, error) {
	state, err := firewallmodule.ServiceStateFromModules(current, modules)
	if err != nil {
		return firewallmodule.ServiceState{}, 0, err
	}
	if err := firewallmodule.ValidateServiceState(state); err != nil {
		return firewallmodule.ServiceState{}, 0, err
	}
	changes := 0
	for packageName, desired := range map[string][]firewallmodule.Section{
		"dhcp":   state.DHCP,
		"stubby": state.Stubby,
		"system": state.System,
	} {
		observed, err := provider.UCIGet(ctx, packageName)
		if err != nil {
			return firewallmodule.ServiceState{}, changes, err
		}
		count, err := firewallmodule.ReconcileOwned(ctx, provider, packageName, observed, desired)
		if err != nil {
			return firewallmodule.ServiceState{}, changes, err
		}
		changes += count
	}
	// Service policy is part of the firewall's composed desired state. This
	// preserves 4A segmentation while adding/removing appliance services.
	observedFirewall, err := provider.UCIGet(ctx, "firewall")
	if err != nil {
		return firewallmodule.ServiceState{}, changes, err
	}
	firewallDesired, err := firewallmodule.DesiredFromSiteWithServices(current, modules)
	if err != nil {
		return firewallmodule.ServiceState{}, changes, err
	}
	count, err := firewallmodule.ReconcileOwned(ctx, provider, "firewall", observedFirewall, firewallDesired.Firewall)
	if err != nil {
		return firewallmodule.ServiceState{}, changes, err
	}
	return state, changes + count, nil
}

func clientServiceChangeCount(ctx context.Context, provider *openwrt.Client, current model.Site, modules clientservices.Modules) (int, error) {
	state, err := firewallmodule.ServiceStateFromModules(current, modules)
	if err != nil {
		return 0, err
	}
	changes := 0
	for packageName, desired := range map[string][]firewallmodule.Section{"dhcp": state.DHCP, "stubby": state.Stubby, "system": state.System} {
		observed, err := provider.UCIGet(ctx, packageName)
		if err != nil {
			return 0, err
		}
		changes += len(firewallmodule.DiffOwned(observed, desired))
	}
	firewallDesired, err := firewallmodule.DesiredFromSiteWithServices(current, modules)
	if err != nil {
		return 0, err
	}
	observed, err := provider.UCIGet(ctx, "firewall")
	if err != nil {
		return 0, err
	}
	return changes + len(firewallmodule.DiffOwned(observed, firewallDesired.Firewall)), nil
}

func verifyClientServices(ctx context.Context, provider *openwrt.Client, state firewallmodule.ServiceState, capability string) error {
	services, err := provider.ServiceList(ctx)
	if err != nil {
		return err
	}
	if len(state.DHCP) > 0 && !bytes.Contains(services, []byte("dnsmasq")) {
		return errors.New("provider dnsmasq service is not present in native service readback")
	}
	if capability == "dns" && len(state.Stubby) > 0 && !bytes.Contains(services, []byte("stubby")) {
		return errors.New("provider stubby service is not present in native service readback")
	}
	if len(state.System) > 0 && !bytes.Contains(services, []byte("sysntpd")) && !bytes.Contains(services, []byte("ntpd")) {
		return errors.New("provider native time service is not present in native service readback")
	}
	return nil
}

func runClientServiceLifecycle(capability, action string, args []string, input io.Reader, out, errOut io.Writer) error {
	allowYes := action == "apply" || action == "teardown" || action == "test"
	allowPlan := action == "plan" || action == "teardown" || action == "test"
	options, err := parseClientServiceOptions("module "+capability+" "+action, args, allowYes, allowPlan)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
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
	lock, err := acquireClientServicesLock()
	if err != nil {
		return err
	}
	defer lock.Release()
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
	modules := serviceContext.Config.Modules.Normalize()
	state, err := firewallmodule.ServiceStateFromModules(serviceContext.Site, modules)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "%s plan\n", strings.ToUpper(capability))
	if (capability == "dns" && serviceContext.Config.Modules.DNS == nil) || (capability == "dhcp" && serviceContext.Config.Modules.DHCP == nil) {
		fmt.Fprintf(out, "  Configuration: create reference %s defaults\n", capability)
	}
	for packageName, sections := range map[string][]firewallmodule.Section{"dhcp": state.DHCP, "stubby": state.Stubby, "system": state.System} {
		current, err := provider.UCIGet(ctx, packageName)
		if err != nil {
			return err
		}
		changes := firewallmodule.DiffOwned(current, sections)
		fmt.Fprintf(out, "  %s: %d owned change(s)\n", packageName, len(changes))
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
		fmt.Fprintf(out, "%s: FAIL\nReason: %s\n", strings.ToUpper(capability), err)
		return err
	}
	fmt.Fprintf(out, "%s: PASS\nService: native provider configuration and readiness verified\n", strings.ToUpper(capability))
	return nil
}

func runClientServiceApply(ctx context.Context, capability string, serviceContext clientServiceContext, provider *openwrt.Client, options clientServiceOptions, input io.Reader, out, errOut io.Writer) error {
	proposed := serviceContext.Config.Modules
	if capability == "dns" {
		if proposed.DNS == nil {
			proposed.DNS = &clientservices.DNSConfig{Enabled: boolPointer(true)}
		} else {
			proposed.DNS.Enabled = boolPointer(true)
		}
		if proposed.DHCP != nil && clientservices.Enabled(proposed.DHCP.Enabled) && (proposed.DNS == nil || !clientservices.Enabled(proposed.DNS.Enabled)) {
			return errors.New("DHCP requires an enabled local DNS capability")
		}
	} else {
		if proposed.DNS == nil || !clientservices.Enabled(proposed.DNS.Enabled) {
			return errors.New("DHCP requires configured usable DNS; run boetticher module dns apply --yes first")
		}
		if proposed.DHCP == nil {
			proposed.DHCP = &clientservices.DHCPConfig{Enabled: boolPointer(true)}
		} else {
			proposed.DHCP.Enabled = boolPointer(true)
		}
	}
	proposed = proposed.Normalize()
	if err := clientservices.Validate(proposed, serviceContext.Site); err != nil {
		return err
	}
	state, err := firewallmodule.ServiceStateFromModules(serviceContext.Site, proposed)
	if err != nil {
		return err
	}
	changes, err := clientServiceChangeCount(ctx, provider, serviceContext.Site, proposed)
	if err != nil {
		return err
	}
	if changes == 0 {
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
	if _, _, err := reconcileClientServices(ctx, provider, serviceContext.Site, proposed); err != nil {
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

func runClientServiceTeardown(ctx context.Context, capability string, serviceContext clientServiceContext, provider *openwrt.Client, options clientServiceOptions, input io.Reader, out io.Writer) error {
	if capability == "dns" && serviceContext.Config.Modules.DHCP != nil && clientservices.Enabled(serviceContext.Config.Modules.DHCP.Enabled) {
		return errors.New("DNS teardown refused while DHCP is enabled; run module dhcp teardown first")
	}
	configured := serviceContext.Config.Modules.DNS != nil
	if capability == "dhcp" {
		configured = serviceContext.Config.Modules.DHCP != nil
	}
	if !configured {
		fmt.Fprintf(out, "%s teardown: already disabled/no change\n", strings.ToUpper(capability))
		return nil
	}
	if options.plan {
		fmt.Fprintf(out, "%s teardown will disable its service and preserve desired records/reservations\nNo mutation or confirmation prompt\n", strings.ToUpper(capability))
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
	if capability == "dns" {
		serviceContext.Config.Modules.DNS.Enabled = boolPointer(false)
	} else {
		serviceContext.Config.Modules.DHCP.Enabled = boolPointer(false)
	}
	ensureClientNetworkIntent(&serviceContext.Config)
	if err := controllerhost.SaveConfig(serviceContext.Config); err != nil {
		return err
	}
	if _, _, err := reconcileClientServices(ctx, provider, serviceContext.Site, serviceContext.Config.Modules); err != nil {
		fmt.Fprintln(out, "Configuration saved; application failed.")
		return err
	}
	fmt.Fprintf(out, "%s teardown: PASS\n", strings.ToUpper(capability))
	return nil
}

func runClientServiceTest(ctx context.Context, capability string, serviceContext clientServiceContext, options clientServiceOptions, input io.Reader, out, errOut io.Writer) error {
	if options.plan {
		fmt.Fprintf(out, "%s test plan\n  one temporary client fixture on each intended LAB zone\n  DHCP allocation, DNS, and NTP observations remain read-only to Host root state\n", strings.ToUpper(capability))
		return nil
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
	zones, err := clientServiceTestZones(serviceContext)
	if err != nil {
		return err
	}
	request := firewalltest.Request{Version: firewalltest.ProtocolVersion, Action: "client-services", Service: capability, Zones: zones}
	if capability == "dns" && len(serviceContext.Config.Modules.DNS.Records) > 0 {
		request.DNSHost, _ = clientservices.CanonicalName(serviceContext.Config.Modules.DNS.Records[0].Name, labConfigDomain(serviceContext.Config))
	}
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

func clientServiceTestZones(serviceContext clientServiceContext) ([]firewalltest.Zone, error) {
	if serviceContext.Config.Modules.DHCP == nil || !clientservices.Enabled(serviceContext.Config.Modules.DHCP.Enabled) {
		return nil, errors.New("client-service tests require enabled DHCP so each fixture can use a real lease")
	}
	normalized := serviceContext.Config.Modules.Normalize()
	scopes := map[string]clientservices.DHCPScope{}
	for _, scope := range normalized.DHCP.Scopes {
		scopes[strings.ToUpper(scope.Zone)] = scope
	}
	reservations := map[string][]clientservices.Reservation{}
	for _, reservation := range normalized.DHCP.Reservations {
		reservations[strings.ToUpper(reservation.Zone)] = append(reservations[strings.ToUpper(reservation.Zone)], reservation)
	}
	zones := make([]firewalltest.Zone, 0, len(serviceContext.Site.Network.Zones))
	for _, zone := range serviceContext.Site.Network.Zones {
		fixture := firewalltest.Zone{Name: zone.Name, Type: string(zone.Type), VLAN: zone.VLAN, Subnet: zone.Network, Gateway: zone.Gateway}
		scope := scopes[strings.ToUpper(zone.Name)]
		fixture.DHCPMode = scope.Mode
		if scope.Mode == clientservices.ScopeReservationsOnly {
			entries := reservations[strings.ToUpper(zone.Name)]
			if len(entries) == 0 {
				return nil, fmt.Errorf("reservation-only scope %s has no working reserved client for a positive control", zone.Name)
			}
			reservation := entries[0]
			fixture.Address, fixture.ClientMAC, fixture.ExpectedName = reservation.Address, reservation.MAC, reservation.Name
		}
		zones = append(zones, fixture)
	}
	return zones, nil
}

func boolPointer(value bool) *bool { return &value }

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
	if len(args) != 0 {
		return errors.New("usage: boetticher module dhcp list-leases")
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
	result, err := serviceContext.Host.Run(ctx, "set -eu; qm guest exec "+fmt.Sprint(firewallmodule.ProviderVMID)+" --synchronous 1 -- /bin/cat "+clientservices.LeaseFilePath)
	if err != nil {
		return fmt.Errorf("read native DHCP leases: %w", err)
	}
	var response struct {
		ExitCode int    `json:"exitcode"`
		Data     string `json:"out-data"`
		Error    string `json:"err-data"`
	}
	if err := json.Unmarshal(result.Stdout, &response); err != nil {
		return errors.New("provider guest agent returned malformed DHCP lease state")
	}
	if response.ExitCode != 0 {
		return fmt.Errorf("read native DHCP leases failed (%d): %s", response.ExitCode, strings.TrimSpace(response.Error))
	}
	if strings.TrimSpace(response.Data) == "" {
		fmt.Fprintln(out, "DHCP leases: none")
		return nil
	}
	fmt.Fprint(out, response.Data)
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
	serviceContext, err := loadClientServiceContext()
	if err != nil {
		return err
	}
	if serviceContext.Config.Modules.DHCP == nil || !clientservices.Enabled(serviceContext.Config.Modules.DHCP.Enabled) {
		return errors.New("DHCP capability is not configured; run boetticher module dhcp apply --yes first")
	}
	reservation := clientservices.Reservation{Name: strings.ToLower(strings.TrimSpace(name)), Zone: strings.ToUpper(strings.TrimSpace(*zone)), MAC: strings.TrimSpace(*mac), Address: strings.TrimSpace(*address)}
	for _, existing := range serviceContext.Config.Modules.DHCP.Reservations {
		if strings.EqualFold(existing.Name, reservation.Name) {
			if strings.EqualFold(existing.Zone, reservation.Zone) && existing.Address == reservation.Address && strings.EqualFold(existing.MAC, reservation.MAC) {
				fmt.Fprintf(out, "DHCP reservation %s.%s: No changes required.\n", reservation.Name, labConfigDomain(serviceContext.Config))
				return nil
			}
			return fmt.Errorf("DHCP reservation %s already exists with a conflicting definition", reservation.Name)
		}
	}
	serviceContext.Config.Modules.DHCP.Reservations = append(serviceContext.Config.Modules.DHCP.Reservations, reservation)
	if err := clientservices.Validate(serviceContext.Config.Modules, serviceContext.Site); err != nil {
		return err
	}
	return applyClientResourceMutation(serviceContext, "DHCP reservation "+reservation.Name, *yes, input, out)
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
	serviceContext.Config.Modules.DHCP.Reservations = append(serviceContext.Config.Modules.DHCP.Reservations[:index], serviceContext.Config.Modules.DHCP.Reservations[index+1:]...)
	return applyClientResourceMutation(serviceContext, "remove DHCP reservation "+name, *yes, input, out)
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
	}
	canonical, err := clientservices.CanonicalName(record.Name, labConfigDomain(serviceContext.Config))
	if err != nil {
		return err
	}
	record.Name = canonical
	for _, existing := range serviceContext.Config.Modules.DNS.Records {
		existingName, _ := clientservices.CanonicalName(existing.Name, labConfigDomain(serviceContext.Config))
		if existingName == canonical {
			if existing.Type == record.Type && existing.Value == record.Value {
				fmt.Fprintf(out, "DNS record %s: No changes required.\n", canonical)
				return nil
			}
			return fmt.Errorf("DNS record %s already exists with a conflicting definition", canonical)
		}
	}
	serviceContext.Config.Modules.DNS.Records = append(serviceContext.Config.Modules.DNS.Records, record)
	if err := clientservices.Validate(serviceContext.Config.Modules, serviceContext.Site); err != nil {
		return err
	}
	return applyClientResourceMutation(serviceContext, "DNS record "+canonical, *yes, input, out)
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
	return applyClientResourceMutation(serviceContext, "remove DNS record "+canonical, *yes, input, out)
}

func applyClientResourceMutation(serviceContext clientServiceContext, description string, yes bool, input io.Reader, out io.Writer) error {
	lock, err := acquireClientServicesLock()
	if err != nil {
		return err
	}
	defer lock.Release()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	provider, err := requireClientProvider(ctx, serviceContext.Site, serviceContext.Desired, serviceContext.Host)
	if err != nil {
		return err
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
	if err := controllerhost.SaveConfig(serviceContext.Config); err != nil {
		return err
	}
	if _, _, err := reconcileClientServices(ctx, provider, serviceContext.Site, serviceContext.Config.Modules); err != nil {
		fmt.Fprintln(out, "Configuration saved; application failed.")
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
