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
	"reflect"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/airvpn"
	"github.com/gofastercloud/boetticher/internal/clientservices"
	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"github.com/gofastercloud/boetticher/internal/firewallmodule"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/openwrt"
	"github.com/gofastercloud/boetticher/internal/pathguard"
	"github.com/gofastercloud/boetticher/internal/site"
)

const (
	vpnStateRootEnv = "BOETTICHER_VPN_STATE_DIR"
	vpnProfileFile  = "wireguard.conf"
	vpnDeviceFile   = "device-id"
	vpnPendingFile  = "device-create.pending"
)

type vpnOptions struct {
	yes         bool
	plan        bool
	details     bool
	apiKeyStdin bool
}

func runVPNCapability(action string, args []string, input io.Reader, out, errOut io.Writer) error {
	if action != "plan" && action != "apply" && action != "status" && action != "teardown" && action != "add-client" && action != "remove-client" {
		return fmt.Errorf("module capability %q does not implement action %q", "vpn", action)
	}
	if action == "add-client" {
		return runVPNAddClient(args, input, out, errOut)
	}
	if action == "remove-client" {
		return runVPNRemoveClient(args, input, out, errOut)
	}
	opts, err := parseVPNOptions(action, args)
	if err != nil {
		return err
	}
	if opts.apiKeyStdin && action != "apply" {
		return errors.New("--api-key-stdin is only valid for module vpn apply")
	}
	if (action == "plan" || action == "status") && opts.yes {
		return errors.New("--yes is only valid for module vpn apply or teardown")
	}
	if opts.apiKeyStdin && !opts.yes {
		return errors.New("--api-key-stdin requires --yes")
	}
	if action == "status" {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		serviceContext, err := loadClientServiceContext()
		if err != nil {
			return err
		}
		return runVPNStatus(ctx, serviceContext, opts, out)
	}
	var lock *site.OperationLock
	if action == "apply" || action == "teardown" {
		lock, err = acquireClientServicesLock()
		if err != nil {
			return err
		}
		defer lock.Release()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	serviceContext, err := loadClientServiceContext()
	if err != nil {
		return err
	}
	switch action {
	case "plan":
		return runVPNPlan(ctx, serviceContext, out)
	case "apply":
		return runVPNApply(ctx, serviceContext, opts, input, out, errOut)
	case "teardown":
		return runVPNTeardown(ctx, serviceContext, opts, input, out)
	default:
		return errors.New("unreachable VPN action")
	}
}

func runVPNRemoveClient(args []string, input io.Reader, out, errOut io.Writer) error {
	if len(args) == 2 && args[1] == "--yes" {
		args = []string{"--yes", args[0]}
	}
	fs := flag.NewFlagSet("module vpn remove-client", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	yes := fs.Bool("yes", false, "approve the VPN client change")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: boetticher module vpn remove-client RESERVATION [--yes]")
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
	if serviceContext.Config.Modules.VPN == nil {
		return errors.New("VPN capability is not configured")
	}
	canonical := strings.ToLower(strings.TrimSpace(fs.Arg(0)))
	proposed := serviceContext.Config.Modules.Clone()
	copyVPN := *proposed.VPN
	clients := make([]string, 0, len(copyVPN.Clients))
	found := false
	for _, existing := range copyVPN.Clients {
		if existing == canonical {
			found = true
			continue
		}
		clients = append(clients, existing)
	}
	if !found {
		return fmt.Errorf("VPN client %q is not configured", canonical)
	}
	for _, forward := range copyVPN.Forwards {
		if forward.Reservation == canonical {
			return fmt.Errorf("VPN client %q has dependent forward %q; remove the forward first", canonical, forward.Name)
		}
	}
	copyVPN.Clients = clients
	proposed.VPN = &copyVPN
	if err := clientservices.Validate(proposed, serviceContext.Site); err != nil {
		return err
	}
	serviceContext.Config.Modules = proposed
	return runVPNApply(context.Background(), serviceContext, vpnOptions{yes: *yes}, input, out, errOut)
}

func runVPNAddClient(args []string, input io.Reader, out, errOut io.Writer) error {
	if len(args) == 2 && args[1] == "--yes" {
		args = []string{"--yes", args[0]}
	}
	fs := flag.NewFlagSet("module vpn add-client", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	yes := fs.Bool("yes", false, "approve the VPN client change")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: boetticher module vpn add-client RESERVATION [--yes]")
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
	proposed, _, err := prepareVPNModules(serviceContext.Config.Modules, serviceContext.Site)
	if err != nil {
		return err
	}
	reservation := fs.Arg(0)
	if _, ok := clientservices.ResolveReservation(proposed, reservation); !ok {
		return fmt.Errorf("VPN client %q does not reference an existing DHCP reservation", reservation)
	}
	canonical := strings.ToLower(strings.TrimSpace(reservation))
	for _, existing := range proposed.VPN.Clients {
		if existing == canonical {
			return fmt.Errorf("VPN client %q is already configured", canonical)
		}
	}
	proposed.VPN.Clients = append(proposed.VPN.Clients, canonical)
	if err := clientservices.Validate(proposed, serviceContext.Site); err != nil {
		return err
	}
	serviceContext.Config.Modules = proposed
	return runVPNApply(context.Background(), serviceContext, vpnOptions{yes: *yes}, input, out, errOut)
}

func parseVPNOptions(action string, args []string) (vpnOptions, error) {
	fs := flag.NewFlagSet("module vpn "+action, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	opts := vpnOptions{}
	fs.BoolVar(&opts.yes, "yes", false, "approve the VPN capability change")
	if action == "plan" || action == "teardown" {
		fs.BoolVar(&opts.plan, "plan", false, "preview the VPN capability change")
	}
	if action == "status" {
		fs.BoolVar(&opts.details, "details", false, "show bounded connection and enforcement details")
	}
	if action == "apply" {
		fs.BoolVar(&opts.apiKeyStdin, "api-key-stdin", false, "read the account API key once from stdin")
	}
	if err := fs.Parse(args); err != nil {
		return vpnOptions{}, err
	}
	if fs.NArg() != 0 {
		return vpnOptions{}, fmt.Errorf("usage: boetticher module vpn %s [flags]", action)
	}
	if opts.plan && opts.yes {
		return vpnOptions{}, errors.New("--plan cannot be combined with --yes")
	}
	return opts, nil
}

func vpnStateDir(s model.Site) string {
	root := os.Getenv(vpnStateRootEnv)
	if root == "" {
		root = "/var/lib/boetticher/controller/vpn"
	}
	id := s.SecretMetadata.InstallationID
	if id == "" {
		id = "default"
	}
	return filepath.Join(root, id)
}

func vpnStatePath(s model.Site, name string) string { return filepath.Join(vpnStateDir(s), name) }

func readVPNStateFile(path string, limit int64) ([]byte, error) {
	if err := pathguard.ValidateNoSymlinkComponents(path); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("VPN state file %s is not a private regular file", filepath.Base(path))
	}
	return pathguard.ReadFileLimited(path, limit)
}

func loadVPNMaterial(s model.Site) (airvpn.Profile, string, bool, error) {
	if _, err := os.Stat(vpnStatePath(s, vpnPendingFile)); err == nil {
		return airvpn.Profile{}, "", false, errors.New("VPN device provisioning has an uncertain outcome; inspect the AirVPN account before retrying")
	}
	profileData, profileErr := readVPNStateFile(vpnStatePath(s, vpnProfileFile), 128*1024)
	deviceData, deviceErr := readVPNStateFile(vpnStatePath(s, vpnDeviceFile), 4096)
	if errors.Is(profileErr, os.ErrNotExist) && errors.Is(deviceErr, os.ErrNotExist) {
		return airvpn.Profile{}, "", false, nil
	}
	if errors.Is(profileErr, os.ErrNotExist) && deviceErr == nil {
		deviceID := strings.TrimSpace(string(deviceData))
		if deviceID == "" || strings.ContainsAny(deviceID, " \t\r\n/\\") {
			return airvpn.Profile{}, "", false, errors.New("retained VPN device identity is malformed")
		}
		// A returned device ID survives profile-generation failure. Explicit
		// provisioning retry can generate against it without creating again.
		return airvpn.Profile{}, deviceID, false, nil
	}
	if profileErr != nil || deviceErr != nil {
		return airvpn.Profile{}, "", false, fmt.Errorf("load retained VPN material: profile=%v device=%v", profileErr, deviceErr)
	}
	profile, err := airvpn.ParseProfileStrict(profileData)
	if err != nil {
		return airvpn.Profile{}, "", false, fmt.Errorf("retained VPN profile is invalid: %w", err)
	}
	deviceID := strings.TrimSpace(string(deviceData))
	if deviceID == "" || strings.ContainsAny(deviceID, " \t\r\n/\\") {
		return airvpn.Profile{}, "", false, errors.New("retained VPN device identity is malformed")
	}
	return profile, deviceID, true, nil
}

func saveVPNMaterial(s model.Site, profile airvpn.Profile, deviceID string) error {
	if strings.TrimSpace(deviceID) == "" || strings.ContainsAny(deviceID, " \t\r\n/\\") {
		return errors.New("VPN device identity is malformed")
	}
	dir := vpnStateDir(s)
	if err := pathguard.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create retained VPN state: %w", err)
	}
	if err := pathguard.WriteFileWithParentMode(vpnStatePath(s, vpnDeviceFile), []byte(deviceID+"\n"), 0600, 0700); err != nil {
		return fmt.Errorf("store retained VPN device identity: %w", err)
	}
	if err := pathguard.WriteFileWithParentMode(vpnStatePath(s, vpnProfileFile), []byte(profile.Config), 0600, 0700); err != nil {
		return fmt.Errorf("store retained VPN profile: %w", err)
	}
	return nil
}

func readVPNAPIKey(input io.Reader) (string, error) {
	if input == nil {
		return "", errors.New("--api-key-stdin requires an API key on stdin")
	}
	data, err := io.ReadAll(io.LimitReader(input, 4097))
	if err != nil {
		return "", fmt.Errorf("read AirVPN API key from stdin: %w", err)
	}
	if len(data) > 4096 {
		return "", errors.New("AirVPN API key exceeds the safe input limit")
	}
	key := strings.TrimSpace(string(data))
	if key == "" || strings.ContainsAny(key, " \t\r\n") {
		return "", errors.New("AirVPN API key is empty or contains whitespace")
	}
	return key, nil
}

func prepareVPNModules(current clientservices.Modules, siteModel model.Site) (clientservices.Modules, bool, error) {
	proposed := current.Clone()
	if proposed.VPN == nil {
		proposed.VPN = &clientservices.VPNConfig{Enabled: boolPointer(true), Location: "europe"}
	} else {
		copyVPN := *proposed.VPN
		copyVPN.Enabled = boolPointer(true)
		proposed.VPN = &copyVPN
	}
	if strings.ToLower(strings.TrimSpace(proposed.VPN.Location)) != "europe" {
		return clientservices.Modules{}, false, errors.New("VPN location must be the configured Europe selection")
	}
	proposed.VPN.Location = "europe"
	if err := clientservices.Validate(proposed, siteModel); err != nil {
		return clientservices.Modules{}, false, err
	}
	return proposed, !reflect.DeepEqual(current, proposed), nil
}

func vpnProfileProjection(profile airvpn.Profile) (firewallmodule.VPNProfile, error) {
	settings, err := profile.WireGuardSettings()
	if err != nil {
		return firewallmodule.VPNProfile{}, err
	}
	return firewallmodule.VPNProfile{PrivateKey: settings.PrivateKey, Address: settings.Address, PeerPublicKey: settings.PeerPublicKey, PresharedKey: settings.PresharedKey, EndpointHost: settings.EndpointHost, EndpointPort: settings.EndpointPort, MTU: settings.MTU, PersistentKeepalive: settings.PersistentKeepalive}, nil
}

func ensureVPNProfile(ctx context.Context, serviceContext clientServiceContext, modules clientservices.Modules, opts vpnOptions, input io.Reader) (airvpn.Profile, string, error) {
	profile, deviceID, present, err := loadVPNMaterial(serviceContext.Site)
	if err != nil {
		return airvpn.Profile{}, "", err
	}
	if present && !opts.apiKeyStdin {
		return profile, deviceID, nil
	}
	if !opts.apiKeyStdin {
		return airvpn.Profile{}, "", errors.New("VPN profile is absent; rerun apply with --api-key-stdin --yes to provision it")
	}
	apiKey, err := readVPNAPIKey(input)
	if err != nil {
		return airvpn.Profile{}, "", err
	}
	client := airvpn.Client{}
	if deviceID == "" {
		pending := vpnStatePath(serviceContext.Site, vpnPendingFile)
		if err := pathguard.MkdirAll(vpnStateDir(serviceContext.Site), 0700); err != nil {
			return airvpn.Profile{}, "", err
		}
		if err := pathguard.WriteFileWithParentMode(pending, []byte("account device creation started\n"), 0600, 0700); err != nil {
			return airvpn.Profile{}, "", fmt.Errorf("persist VPN provisioning uncertainty marker: %w", err)
		}
		deviceID, err = client.CreateDevice(ctx, apiKey)
		if err != nil {
			return airvpn.Profile{}, "", err
		}
		if err := pathguard.WriteFileWithParentMode(vpnStatePath(serviceContext.Site, vpnDeviceFile), []byte(deviceID+"\n"), 0600, 0700); err != nil {
			return airvpn.Profile{}, "", err
		}
		if err := pathguard.RemoveAll(pending); err != nil {
			return airvpn.Profile{}, "", fmt.Errorf("clear VPN provisioning uncertainty marker: %w", err)
		}
	}
	profile, err = client.GenerateForDevice(ctx, apiKey, modules.VPN.Location, deviceID)
	if err != nil {
		return airvpn.Profile{}, "", err
	}
	if err := saveVPNMaterial(serviceContext.Site, profile, deviceID); err != nil {
		return airvpn.Profile{}, "", err
	}
	return profile, deviceID, nil
}

func vpnChangeCount(ctx context.Context, provider *openwrt.Client, serviceContext clientServiceContext, modules clientservices.Modules) (int, error) {
	composition, err := composeClientAppliance(serviceContext, modules)
	if err != nil {
		return 0, err
	}
	state, err := firewallmodule.ServiceStateFromModules(serviceContext.Site, modules)
	if err != nil {
		return 0, err
	}
	items := []struct {
		name    string
		desired []firewallmodule.Section
	}{
		{"network", composition.Network}, {"firewall", composition.Firewall}, {"system", state.System}, {"stubby", state.Stubby}, {"dhcp", state.DHCP},
	}
	changes := 0
	for _, item := range items {
		observed, err := provider.UCIGet(ctx, item.name)
		if err != nil {
			return 0, err
		}
		if err := firewallmodule.ValidateServicePackage(item.name, observed, item.desired); err != nil {
			return 0, err
		}
		mutations, err := firewallmodule.DiffOwned(observed, item.desired)
		if err != nil {
			return 0, err
		}
		changes += len(mutations)
	}
	return changes, nil
}

func runVPNApply(ctx context.Context, serviceContext clientServiceContext, opts vpnOptions, input io.Reader, out, errOut io.Writer) error {
	modules, configChanged, err := prepareVPNModules(serviceContext.Config.Modules, serviceContext.Site)
	if err != nil {
		return err
	}
	provider, err := requireClientProvider(ctx, serviceContext.Site, serviceContext.Desired, serviceContext.Host)
	if err != nil {
		return err
	}
	profile, _, err := ensureVPNProfile(ctx, serviceContext, modules, opts, input)
	if err != nil {
		return err
	}
	projection, err := vpnProfileProjection(profile)
	if err != nil {
		return err
	}
	serviceContext.VPNProfile = &projection
	changes, err := vpnChangeCount(ctx, provider, serviceContext, modules)
	if err != nil {
		return err
	}
	state, err := firewallmodule.ServiceStateFromModules(serviceContext.Site, modules)
	if err != nil {
		return err
	}
	if changes == 0 && !configChanged {
		if _, err := verifyVPN(ctx, provider, serviceContext, modules, state, out); err != nil {
			return err
		}
		fmt.Fprintln(out, "VPN: CONNECTED\nConnection: connected\nEgress: unverified\nEnforcement: present")
		return nil
	}
	if !opts.yes {
		answer, promptErr := promptYesNo(bufio.NewReader(input), out, "Apply VPN connection and protected egress policy? [y/N]: ", false)
		if promptErr != nil {
			return promptErr
		}
		if !answer {
			return errors.New("module vpn apply cancelled")
		}
	}
	serviceContext.Config.Modules = modules
	if err := controllerhost.SaveConfig(serviceContext.Config); err != nil {
		return err
	}
	if _, _, err := reconcileClientServices(ctx, provider, serviceContext, modules); err != nil {
		fmt.Fprintln(out, "Configuration saved; application failed.")
		return fmt.Errorf("reconcile VPN configuration: %w", err)
	}
	if _, err := verifyVPN(ctx, provider, serviceContext, modules, state, out); err != nil {
		return err
	}
	fmt.Fprintf(out, "VPN: CONNECTED\nConfiguration: saved\nConnection: connected\nEgress: unverified\nEnforcement: present\n")
	_ = errOut
	return nil
}

func verifyVPN(ctx context.Context, provider *openwrt.Client, serviceContext clientServiceContext, modules clientservices.Modules, state firewallmodule.ServiceState, out io.Writer) (firewallmodule.VPNRuntimeStatus, error) {
	composition, err := composeClientAppliance(serviceContext, modules)
	if err != nil {
		return firewallmodule.VPNRuntimeStatus{}, err
	}
	pendingAdditions := false
	for _, item := range []struct {
		name    string
		desired []firewallmodule.Section
	}{{"network", composition.Network}, {"firewall", composition.Firewall}, {"system", state.System}, {"stubby", state.Stubby}, {"dhcp", state.DHCP}} {
		observed, err := provider.UCIGet(ctx, item.name)
		if err != nil {
			return firewallmodule.VPNRuntimeStatus{}, err
		}
		if err := firewallmodule.ValidateServicePackage(item.name, observed, item.desired); err != nil {
			return firewallmodule.VPNRuntimeStatus{}, err
		}
		mutations, err := firewallmodule.DiffOwned(observed, item.desired)
		if err != nil {
			return firewallmodule.VPNRuntimeStatus{}, err
		}
		if len(mutations) > 0 {
			if item.name == "dhcp" {
				benign := true
				for _, mutation := range mutations {
					if mutation.Kind != firewallmodule.MutationCreate || !(strings.HasPrefix(mutation.Section.Name, "boetticher_record_") || strings.HasPrefix(mutation.Section.Name, "boetticher_observability_record_") || strings.HasPrefix(mutation.Section.Name, "boetticher_host_")) {
						benign = false
						break
					}
				}
				if benign {
					pendingAdditions = true
					continue
				}
			}
			return firewallmodule.VPNRuntimeStatus{}, fmt.Errorf("provider %s configuration is not at the desired VPN state", item.name)
		}
	}
	ok, err := firewallmodule.FirewallSafetyStatusViaHost(ctx, serviceContext.Host)
	if err != nil {
		return firewallmodule.VPNRuntimeStatus{}, err
	}
	if !ok {
		return firewallmodule.VPNRuntimeStatus{}, errors.New("VPN enforcement safety status failed")
	}
	runtime, err := firewallmodule.VPNRuntimeStatusViaHost(ctx, serviceContext.Host)
	if err != nil {
		fmt.Fprintln(out, "Connection: unavailable\nEnforcement: present; protected clients remain blocked")
		return firewallmodule.VPNRuntimeStatus{}, err
	}
	if !runtime.InterfaceUp || !runtime.PeerSeen {
		fmt.Fprintln(out, "Connection: unavailable\nEnforcement: present; protected clients remain blocked")
		return runtime, errors.New("VPN connection is unavailable; protected clients remain blocked")
	}
	if age := time.Since(runtime.LatestHandshake); age > 10*time.Minute {
		fmt.Fprintln(out, "Connection: stale\nEnforcement: present; protected clients remain blocked")
		return runtime, errors.New("VPN peer handshake is stale; protected clients remain blocked")
	}
	if pendingAdditions {
		return runtime, pendingVPNStatusError{}
	}
	return runtime, nil
}

type pendingVPNStatusError struct{}

func (pendingVPNStatusError) Error() string {
	return "VPN status has pending additive DNS or reservation intent"
}

func runVPNStatus(ctx context.Context, serviceContext clientServiceContext, opts vpnOptions, out io.Writer) error {
	vpn := serviceContext.Config.Modules.VPN
	if vpn == nil || (!clientservices.Enabled(vpn.Enabled) && len(vpn.Clients) == 0) {
		fmt.Fprintln(out, "VPN: OFF\nConnection: not configured\nEnforcement: unknown (no live appliance observation)")
		return nil
	}
	provider, err := requireClientProvider(ctx, serviceContext.Site, serviceContext.Desired, serviceContext.Host)
	if err != nil {
		fmt.Fprintf(out, "VPN: UNAVAILABLE\nConnection: unavailable\nEnforcement: unknown\nReason: %s\n", err)
		return err
	}
	profile, _, present, materialErr := loadVPNMaterial(serviceContext.Site)
	if materialErr != nil || !present {
		reason := "retained VPN profile is absent"
		if materialErr != nil {
			reason = materialErr.Error()
		}
		enforcement := "unknown"
		if safe, safetyErr := firewallmodule.FirewallSafetyStatusViaHost(ctx, serviceContext.Host); safetyErr == nil && safe {
			enforcement = "present; protected clients blocked"
		}
		fmt.Fprintf(out, "VPN: BLOCKED\nConnection: unavailable\nEnforcement: %s\nReason: %s\n", enforcement, reason)
		return errors.New(reason)
	}
	projection, err := vpnProfileProjection(profile)
	if err != nil {
		return err
	}
	serviceContext.VPNProfile = &projection
	state, err := firewallmodule.ServiceStateFromModules(serviceContext.Site, serviceContext.Config.Modules)
	if err != nil {
		return err
	}
	if _, err := verifyVPN(ctx, provider, serviceContext, serviceContext.Config.Modules, state, out); err != nil {
		var pending pendingVPNStatusError
		if errors.As(err, &pending) {
			fmt.Fprintln(out, "VPN: CHECKING\nConnection: available\nEnforcement: verified\nReason: additive DNS or reservation intent is pending provider reconciliation")
			return nil
		}
		if opts.details {
			fmt.Fprintf(out, "Location: %s\nClients: %d\n", vpn.Location, len(vpn.Clients))
		}
		return err
	}
	fmt.Fprintf(out, "VPN: CONNECTED\nConnection: connected\nEgress: unverified\nEnforcement: present\nLocation: %s\nClients: %d\n", vpn.Location, len(vpn.Clients))
	return nil
}

func runVPNPlan(ctx context.Context, serviceContext clientServiceContext, out io.Writer) error {
	vpn := serviceContext.Config.Modules.VPN
	if vpn == nil {
		fmt.Fprintln(out, "VPN plan\n  Configuration: enable vpn and configure the Europe connection\n  No mutation or confirmation prompt")
		return nil
	}
	provider, err := requireClientProvider(ctx, serviceContext.Site, serviceContext.Desired, serviceContext.Host)
	if err != nil {
		return err
	}
	modules := serviceContext.Config.Modules
	profile, _, present, _ := loadVPNMaterial(serviceContext.Site)
	if present {
		projection, projectionErr := vpnProfileProjection(profile)
		if projectionErr != nil {
			return projectionErr
		}
		serviceContext.VPNProfile = &projection
	}
	composition, err := composeClientAppliance(serviceContext, modules)
	if err != nil {
		fmt.Fprintf(out, "VPN plan\n  Connection: provisioning required\n  No mutation or confirmation prompt\n")
		return nil
	}
	changes, err := vpnChangeCount(ctx, provider, serviceContext, modules)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "VPN plan")
	if changes == 0 {
		fmt.Fprintln(out, "  No changes required")
	} else {
		fmt.Fprintf(out, "  Provider: reconcile %d owned change(s)\n", changes)
	}
	if !present {
		fmt.Fprintln(out, "  Connection: provisioning required (--api-key-stdin --yes)")
	}
	_ = composition
	fmt.Fprintln(out, "  No mutation or confirmation prompt")
	return nil
}

func runVPNTeardown(ctx context.Context, serviceContext clientServiceContext, opts vpnOptions, input io.Reader, out io.Writer) error {
	proposed := serviceContext.Config.Modules.Clone()
	if proposed.VPN == nil {
		fmt.Fprintln(out, "VPN teardown: already disabled; protected ranges retained")
		return nil
	}
	copyVPN := *proposed.VPN
	copyVPN.Enabled = boolPointer(false)
	proposed.VPN = &copyVPN
	if err := refuseVPNStopWithLiveProtectedGuests(ctx, serviceContext.Host, serviceContext.Config.Proxmox.Node, serviceContext.Config.Modules); err != nil {
		return err
	}
	provider, err := requireClientProvider(ctx, serviceContext.Site, serviceContext.Desired, serviceContext.Host)
	if err != nil {
		return err
	}
	changes, err := clientServiceChangeCount(ctx, provider, serviceContext, proposed)
	if err != nil {
		return err
	}
	if opts.plan {
		fmt.Fprintf(out, "VPN teardown\n  Provider: reconcile %d owned change(s)\n  Retained: client intent, profile, device identity, protected ranges\n  No mutation or confirmation prompt\n", changes)
		return nil
	}
	if changes == 0 && reflect.DeepEqual(serviceContext.Config.Modules, proposed) {
		fmt.Fprintln(out, "VPN teardown: already disabled/no change")
		return nil
	}
	if !opts.yes {
		answer, promptErr := promptYesNo(bufio.NewReader(input), out, "Disable the VPN connection while retaining protected client intent? [y/N]: ", false)
		if promptErr != nil {
			return promptErr
		}
		if !answer {
			return errors.New("module vpn teardown cancelled")
		}
	}
	if err := refuseVPNStopWithLiveProtectedGuests(ctx, serviceContext.Host, serviceContext.Config.Proxmox.Node, serviceContext.Config.Modules); err != nil {
		return err
	}
	serviceContext.Config.Modules = proposed
	if err := controllerhost.SaveConfig(serviceContext.Config); err != nil {
		return err
	}
	if _, _, err := reconcileClientServices(ctx, provider, serviceContext, proposed); err != nil {
		return err
	}
	fmt.Fprintln(out, "VPN teardown: PASS\nConnection: disabled\nEnforcement: protected ranges retained\nRetained: profile and device identity")
	return nil
}
