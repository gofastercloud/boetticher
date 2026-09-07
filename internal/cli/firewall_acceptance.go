package cli

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"github.com/gofastercloud/boetticher/internal/controllerstatus"
	"github.com/gofastercloud/boetticher/internal/firewallmodule"
	"github.com/gofastercloud/boetticher/internal/firewalltest"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/openwrt"
)

type firewallTestOptions struct {
	yes         bool
	plan        bool
	cleanupOnly bool
}

func parseFirewallTestOptions(args []string) (firewallTestOptions, error) {
	fs := flag.NewFlagSet("module firewall test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	options := firewallTestOptions{}
	fs.BoolVar(&options.yes, "yes", false, "approve the bounded Phase 4A packet test")
	fs.BoolVar(&options.plan, "plan", false, "preview fixtures and expected journeys without mutation")
	fs.BoolVar(&options.cleanupOnly, "cleanup-only", false, "remove only recognised Phase 4A test leftovers")
	if err := fs.Parse(args); err != nil {
		return firewallTestOptions{}, err
	}
	if fs.NArg() != 0 {
		return firewallTestOptions{}, errors.New("usage: boetticher module firewall test [--yes|--plan|--cleanup-only --yes]")
	}
	if options.plan && options.cleanupOnly {
		return firewallTestOptions{}, errors.New("--plan cannot be combined with --cleanup-only")
	}
	if options.plan && options.yes {
		return firewallTestOptions{}, errors.New("--plan cannot be combined with --yes")
	}
	if options.cleanupOnly && !options.yes {
		return firewallTestOptions{}, errors.New("--cleanup-only requires --yes")
	}
	return options, nil
}

func runFirewallTest(args []string, input io.Reader, out, errOut io.Writer) (err error) {
	options, err := parseFirewallTestOptions(args)
	if err != nil {
		return err
	}
	current, desired, host, err := loadFirewallContext()
	if err != nil {
		return err
	}
	fixtures, err := firewallTestFixtures(desired)
	if err != nil {
		return err
	}
	if options.plan {
		renderFirewallTestPlan(out, fixtures)
		return nil
	}
	if options.cleanupOnly {
		return runFirewallTestCleanup(host, out)
	}

	renderFirewallTestScope(out, fixtures)
	if !options.yes {
		if input == nil {
			return errors.New("firewall test requires --yes or an interactive confirmation")
		}
		answer, promptErr := promptYesNo(bufio.NewReader(input), out, "Create temporary firewall test fixtures and run the fixed suite? [y/N]: ", false)
		if promptErr != nil {
			return promptErr
		}
		if !answer {
			return errors.New("firewall test cancelled")
		}
	}

	controllerstatus.NotifyBestEffort(controllerstatus.OperationEvent{Event: "operation-start", Name: "firewall test", Steps: 3})
	defer func() {
		if err != nil {
			controllerstatus.NotifyBestEffort(controllerstatus.OperationEvent{Event: "operation-failure", Name: "firewall test", Detail: err.Error()})
			return
		}
		controllerstatus.NotifyBestEffort(controllerstatus.OperationEvent{Event: "operation-success", Name: "firewall test"})
	}()
	signalContext, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	ctx, cancel := context.WithTimeout(signalContext, 10*time.Minute)
	defer cancel()
	publicAddress, err := resolvePublicProbe(ctx)
	if err != nil {
		return err
	}
	if err := confirmHomeEndpoints(ctx, desired); err != nil {
		return err
	}
	provider, err := firewallProviderClient(current, desired)
	if err != nil {
		return err
	}
	health, err := firewallmodule.CheckHealthViaSSH(ctx, host, desired, provider)
	if err != nil {
		return fmt.Errorf("firewall operational preflight failed: %w", err)
	}
	if !health.Healthy() {
		return fmt.Errorf("firewall operational preflight failed: %s", health.Detail())
	}
	if err := verifyPhase4AScope(ctx, host, provider, desired); err != nil {
		return err
	}
	controllerstatus.NotifyBestEffort(controllerstatus.OperationEvent{Event: "operation-progress", Name: "firewall test", CurrentStep: 1, TotalSteps: 3, Detail: "Provider and HOME paths verified"})

	request := firewalltest.Request{Version: firewalltest.ProtocolVersion, Action: "run", Zones: fixtures, PublicAddress: publicAddress, PublicHost: firewalltest.PublicHost, HomeProxmox: controllerhost.HomeManagementAddress, HomeController: desired.ControllerAddress, ProviderHome: desired.ManagementAddress}
	response, helperErr := invokeFirewallTestHost(ctx, host, request)
	controllerstatus.NotifyBestEffort(controllerstatus.OperationEvent{Event: "operation-progress", Name: "firewall test", CurrentStep: 2, TotalSteps: 3, Detail: "Fixed routed packet suite completed"})
	if ctx.Err() != nil {
		cleanupResponse, cleanupErr := cleanupFirewallTestWithRetry(host)
		if cleanupErr != nil || !cleanupResponse.OK || !cleanupResponse.CleanupOK {
			return fmt.Errorf("firewall test interrupted and cleanup failed: %s", helperResponseDetail(cleanupResponse, cleanupErr))
		}
		if cleanupResponse.CleanupRemoved {
			return errors.New("firewall test interrupted; cleanup-only recovery removed leftover fixtures")
		}
		return errors.New("firewall test interrupted; automatic cleanup completed")
	}

	results := append([]firewalltest.Result(nil), response.Results...)
	adminResult, adminErr := verifyHostAdministrationDenied(ctx, host, desired.ManagementAddress)
	if adminErr != nil {
		results = append(results, firewalltest.Result{Name: "admin/host-provider-home", Group: "Appliance administration", Source: "Host HOME", Target: "firewall HOME", Protocol: "tcp", Expected: "deny", Observed: "execution-error", Status: "FAIL", Detail: adminErr.Error()})
	} else {
		results = append(results, adminResult)
	}
	controllerResult := firewalltest.Result{Name: "admin/controller-provider-home", Group: "Appliance administration", Source: "Controller", Target: "firewall HOME", Protocol: "https", Expected: "allow", Observed: "authenticated", Status: "PASS", Detail: "verified HTTPS API authentication succeeded"}
	results = append(results, controllerResult)
	response.Results = firewalltest.SortedResults(results)

	cleanupResponse, cleanupErr := invokeFirewallTestHost(context.Background(), host, firewalltest.Request{Version: firewalltest.ProtocolVersion, Action: "cleanup"})
	controllerstatus.NotifyBestEffort(controllerstatus.OperationEvent{Event: "operation-progress", Name: "firewall test", CurrentStep: 3, TotalSteps: 3, Detail: "Temporary fixtures cleaned"})
	if cleanupErr != nil || !cleanupResponse.OK || !cleanupResponse.CleanupOK {
		return fmt.Errorf("firewall test cleanup failed: %s", helperResponseDetail(cleanupResponse, cleanupErr))
	}
	passed := helperErr == nil && response.OK && response.CleanupOK && adminErr == nil && !anyFailed(response.Results)
	renderFirewallTestResults(out, response.Results, passed)
	if helperErr != nil || !response.OK || !response.CleanupOK {
		return fmt.Errorf("firewall packet suite failed: %s", helperResponseDetail(response, helperErr))
	}
	if adminErr != nil || anyFailed(response.Results) {
		return errors.New("firewall packet suite failed")
	}
	_ = errOut
	return nil
}

func firewallTestFixtures(desired firewallmodule.DesiredState) ([]firewalltest.Zone, error) {
	zones := make([]firewalltest.Zone, 0, len(desired.Zones))
	for _, zone := range desired.Zones {
		zones = append(zones, firewalltest.Zone{Name: zone.Name, Type: string(zone.Type), VLAN: zone.VLAN, Subnet: zone.Subnet, Gateway: zone.Gateway})
	}
	return firewalltest.Fixtures(zones)
}

func renderFirewallTestScope(out io.Writer, fixtures []firewalltest.Zone) {
	fmt.Fprintln(out, "Firewall test")
	fmt.Fprintln(out, "  Temporary scope: six network namespaces, one veth pair per LAB zone, and one vmbr1 access port per zone")
	fmt.Fprintln(out, "  Preserved: vmbr1 global VLANs, existing guest ports, physical interfaces, provider policy, Host and Controller state")
	fmt.Fprintln(out, "  Cleanup: automatic on completion, failure, timeout, and interruption; recovery is --cleanup-only --yes")
	for _, fixture := range fixtures {
		fmt.Fprintf(out, "  %-8s VLAN %-4d preferred address %s gateway %s\n", fixture.Name, fixture.VLAN, fixture.Address, fixture.Gateway)
	}
}

func renderFirewallTestPlan(out io.Writer, fixtures []firewalltest.Zone) {
	fmt.Fprintln(out, "Firewall test plan (read-only)")
	renderFirewallTestScope(out, fixtures)
	fmt.Fprintln(out, "  Expected policy: independent fixed Phase 4A gateway, egress, inter-zone, HOME, and administration journeys")
	for _, expectation := range firewalltest.ReferenceExpectations() {
		fmt.Fprintf(out, "  %-40s %-5s %s -> %s (%s)\n", expectation.Name, strings.ToUpper(expectation.Expected), expectation.Source, expectation.Target, expectation.Protocol)
	}
	fmt.Fprintln(out, "  No namespaces, listeners, provider state, credentials, or evidence files are created by this preview.")
}

func runFirewallTestCleanup(host firewallmodule.HostClient, out io.Writer) error {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	response, helperErr := invokeFirewallTestHost(ctx, host, firewalltest.Request{Version: firewalltest.ProtocolVersion, Action: "cleanup"})
	if helperErr != nil || !response.OK || !response.CleanupOK {
		return fmt.Errorf("firewall test cleanup failed: %s", helperResponseDetail(response, helperErr))
	}
	if response.CleanupRemoved {
		fmt.Fprintln(out, "Firewall test cleanup: PASS (recognised leftovers removed)")
	} else {
		fmt.Fprintln(out, "Firewall test cleanup: PASS (no recognised leftovers remain)")
	}
	return nil
}

func cleanupFirewallTestWithRetry(host firewallmodule.HostClient) (firewalltest.Response, error) {
	deadline := time.Now().Add(90 * time.Second)
	var last firewalltest.Response
	var lastErr error
	for time.Now().Before(deadline) {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		response, err := invokeFirewallTestHost(cleanupCtx, host, firewalltest.Request{Version: firewalltest.ProtocolVersion, Action: "cleanup"})
		cancel()
		last, lastErr = response, err
		if err == nil && response.OK && response.CleanupOK {
			return response, nil
		}
		if !strings.Contains(helperResponseDetail(response, err), "another firewall test is already running") {
			return response, err
		}
		time.Sleep(2 * time.Second)
	}
	return last, lastErr
}

func invokeFirewallTestHost(ctx context.Context, host firewallmodule.HostClient, request firewalltest.Request) (firewalltest.Response, error) {
	data, err := json.Marshal(request)
	if err != nil {
		return firewalltest.Response{}, fmt.Errorf("encode firewall test request: %w", err)
	}
	result, runErr := host.RunWithStdin(ctx, firewalltest.HelperCommand, bytes.NewReader(data))
	var response firewalltest.Response
	if decodeErr := json.Unmarshal(result.Stdout, &response); decodeErr != nil {
		if runErr != nil {
			return response, fmt.Errorf("firewall test helper transport failed: %w", runErr)
		}
		return response, fmt.Errorf("decode firewall test helper response: %w", decodeErr)
	}
	return response, runErr
}

func firewallProviderClient(current model.Site, desired firewallmodule.DesiredState) (*openwrt.Client, error) {
	stateDir := firewallmodule.StateDir(current)
	credential, err := firewallmodule.LoadCredential(stateDir)
	if err != nil {
		return nil, fmt.Errorf("load firewall provider credential: %w", err)
	}
	trust, err := firewallmodule.LoadTrust(stateDir)
	if err != nil {
		return nil, fmt.Errorf("load firewall provider TLS trust: %w", err)
	}
	return openwrt.NewClient(openwrt.Config{BaseURL: "https://" + desired.ManagementAddress, ServerName: firewallmodule.ProviderTLSName, Username: "boetticher", Password: credential, TrustPEM: trust})
}

func verifyPhase4AScope(ctx context.Context, host firewallmodule.HostClient, provider *openwrt.Client, desired firewallmodule.DesiredState) error {
	if _, err := host.Run(ctx, "set -eu; for unit in kea-dhcp4-server kea-dhcp-ddns-server dnsmasq; do if systemctl is-active --quiet \"$unit\" || systemctl is-enabled --quiet \"$unit\"; then echo \"unexpected active or enabled HOME DHCP service: $unit\" >&2; exit 1; fi; done"); err != nil {
		return fmt.Errorf("read Host HOME DHCP service ownership: %w", err)
	}
	dhcp, err := providerDHCPConfigViaHost(ctx, host)
	if err != nil {
		return fmt.Errorf("read provider DHCP scope: %w", err)
	}
	if err := validateProviderDHCPConfig(dhcp); err != nil {
		return err
	}
	if _, err := provider.UCIGet(ctx, "network"); err != nil {
		return fmt.Errorf("read provider network scope: %w", err)
	}
	if _, err := provider.UCIGet(ctx, "firewall"); err != nil {
		return fmt.Errorf("read provider firewall scope: %w", err)
	}
	if len(desired.Zones) != len(firewalltest.ZoneOrder) {
		return errors.New("Phase 4A scope does not contain exactly six zones")
	}
	return nil
}

func providerDHCPConfigViaHost(ctx context.Context, host firewallmodule.HostClient) (string, error) {
	result, err := host.Run(ctx, "set -eu; qm guest exec "+fmt.Sprint(firewallmodule.ProviderVMID)+" --synchronous 1 -- /bin/cat /etc/config/dhcp")
	if err != nil {
		return "", err
	}
	var response struct {
		ExitCode int    `json:"exitcode"`
		Data     string `json:"out-data"`
		Error    string `json:"err-data"`
	}
	if err := json.Unmarshal(result.Stdout, &response); err != nil {
		return "", errors.New("provider guest agent returned malformed DHCP configuration")
	}
	if response.ExitCode != 0 {
		return "", fmt.Errorf("provider guest agent DHCP configuration read failed (%d): %s", response.ExitCode, strings.TrimSpace(response.Error))
	}
	return response.Data, nil
}

func validateProviderDHCPConfig(config string) error {
	if !strings.Contains(config, "config dhcp 'boetticher_home'") || !strings.Contains(config, "option ignore '1'") {
		return errors.New("provider HOME DHCP ownership is not explicitly disabled")
	}
	for _, line := range strings.Split(config, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "config ") && strings.Contains(line, "'boetticher_") && !strings.Contains(line, "'boetticher_home'") {
			return fmt.Errorf("provider DHCP scope unexpectedly contains %s", line)
		}
	}
	return nil
}

func resolvePublicProbe(ctx context.Context) (string, error) {
	addresses, err := net.DefaultResolver.LookupIP(ctx, "ip4", firewalltest.PublicHost)
	if err != nil {
		return "", fmt.Errorf("resolve public HTTPS test host on Controller HOME path: %w", err)
	}
	values := make([]string, 0, len(addresses))
	for _, address := range addresses {
		if ipv4 := address.To4(); ipv4 != nil {
			parsed := netip.MustParseAddr(ipv4.String())
			if parsed.IsGlobalUnicast() && !parsed.IsPrivate() {
				values = append(values, parsed.String())
			}
		}
	}
	sort.Strings(values)
	for _, address := range values {
		if err := controllerHTTPS(ctx, address); err == nil {
			return address, nil
		}
	}
	return "", errors.New("public HTTPS test service is unavailable through the Controller HOME path; packet acceptance is unproven")
}

func controllerHTTPS(ctx context.Context, address string) error {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp4", net.JoinHostPort(address, "443"))
	}, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: firewalltest.PublicHost}}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+firewalltest.PublicHost+firewalltest.PublicPath, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 400 {
		return fmt.Errorf("public HTTPS test returned %s", response.Status)
	}
	return nil
}

func confirmHomeEndpoints(ctx context.Context, desired firewallmodule.DesiredState) error {
	for _, item := range []struct {
		name, address string
		port          int
	}{
		{"Proxmox HOME HTTPS", controllerhost.HomeManagementAddress, firewalltest.ProxmoxPort},
		{"Controller HOME SSH", desired.ControllerAddress, firewalltest.SSHPort},
	} {
		connection, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp4", net.JoinHostPort(item.address, fmt.Sprint(item.port)))
		if err != nil {
			return fmt.Errorf("confirm %s endpoint %s:%d: %w", item.name, item.address, item.port, err)
		}
		_ = connection.Close()
	}
	return nil
}

func verifyHostAdministrationDenied(ctx context.Context, host firewallmodule.HostClient, providerAddress string) (firewalltest.Result, error) {
	address, err := netip.ParseAddr(providerAddress)
	if err != nil || !address.Is4() {
		return firewalltest.Result{}, errors.New("provider HOME address is malformed")
	}
	command := "python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(2);\ntry: s.connect((\"" + providerAddress + "\",443)); s.close(); raise SystemExit(1)\nexcept OSError: raise SystemExit(0)'"
	result, runErr := host.Run(ctx, command)
	if runErr == nil && result.ExitCode == 0 {
		return firewalltest.Result{Name: "admin/host-provider-home", Group: "Appliance administration", Source: "Host HOME", Target: "firewall HOME", Protocol: "tcp", Expected: "deny", Observed: "blocked", Status: "PASS", Detail: "credential-free Host connection was denied"}, nil
	}
	if result.ExitCode == 1 {
		return firewalltest.Result{Name: "admin/host-provider-home", Group: "Appliance administration", Source: "Host HOME", Target: "firewall HOME", Protocol: "tcp", Expected: "deny", Observed: "reachable", Status: "FAIL", Detail: "Host HOME reached the provider HTTPS port"}, nil
	}
	if runErr != nil {
		return firewalltest.Result{}, fmt.Errorf("credential-free Host administration probe failed: %w", runErr)
	}
	return firewalltest.Result{}, fmt.Errorf("credential-free Host administration probe returned exit code %d", result.ExitCode)
}

func renderFirewallTestResults(out io.Writer, results []firewalltest.Result, passed bool) {
	lastGroup := ""
	for _, result := range results {
		if result.Group != lastGroup {
			fmt.Fprintf(out, "\n%s\n", result.Group)
			lastGroup = result.Group
		}
		fmt.Fprintf(out, "  %-42s %-4s %s\n", result.Name, result.Status, result.Detail)
	}
	if passed {
		fmt.Fprintln(out, "\nFirewall test: PASS")
	} else {
		fmt.Fprintln(out, "\nFirewall test: FAIL")
	}
}

func anyFailed(results []firewalltest.Result) bool {
	for _, result := range results {
		if result.Status != "PASS" {
			return true
		}
	}
	return false
}

func helperResponseDetail(response firewalltest.Response, err error) string {
	parts := []string{}
	if response.Error != "" {
		parts = append(parts, response.Error)
	}
	for _, result := range response.Results {
		if result.Status != "PASS" {
			parts = append(parts, result.Name+": "+result.Detail)
		}
	}
	if err != nil {
		parts = append(parts, err.Error())
	}
	if len(parts) == 0 {
		return "unknown helper failure"
	}
	return strings.Join(parts, "; ")
}
