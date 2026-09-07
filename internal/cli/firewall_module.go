package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/firewallmodule"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/openwrt"
	"github.com/gofastercloud/boetticher/internal/proxmox"
	"github.com/gofastercloud/boetticher/internal/site"
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
	default:
		return fmt.Errorf("module capability %q does not implement action %q", "firewall", action)
	}
}

type firewallCommandOptions struct {
	siteDir     string
	ageIdentity string
	yes         bool
}

func parseFirewallOptions(command string, args []string, destructive bool) (firewallCommandOptions, error) {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	options := firewallCommandOptions{siteDir: ".", ageIdentity: model.DefaultAgeIdentity}
	fs.StringVar(&options.siteDir, "site", ".", "private site repository directory")
	fs.StringVar(&options.ageIdentity, "age-identity", model.DefaultAgeIdentity, "external Age identity path")
	if destructive {
		fs.BoolVar(&options.yes, "yes", false, "approve destructive firewall provider removal")
	} else {
		fs.BoolVar(&options.yes, "yes", false, "approve the firewall capability change")
	}
	if err := fs.Parse(args); err != nil {
		return firewallCommandOptions{}, err
	}
	if fs.NArg() != 0 {
		return firewallCommandOptions{}, fmt.Errorf("usage: boetticher module firewall %s [--site DIR] [--age-identity PATH] [--yes]", command)
	}
	return options, nil
}

func loadFirewallContext(siteDir, ageIdentity string) (model.Site, firewallmodule.DesiredState, *proxmox.Client, string, error) {
	current, err := site.Load(siteDir)
	if err != nil {
		return model.Site{}, firewallmodule.DesiredState{}, nil, "", err
	}
	desired, err := firewallmodule.DesiredFromSite(current)
	if err != nil {
		return model.Site{}, firewallmodule.DesiredState{}, nil, "", fmt.Errorf("validate firewall network intent: %w", err)
	}
	client, _, err := loadProxmoxClient(siteDir, current, ageIdentity, "", false)
	if err != nil {
		return model.Site{}, firewallmodule.DesiredState{}, nil, "", err
	}
	node, err := client.SingleNode(context.Background())
	if err != nil {
		return model.Site{}, firewallmodule.DesiredState{}, nil, "", err
	}
	return current, desired, client, node, nil
}

func runFirewallPlan(args []string, out io.Writer) error {
	options, err := parseFirewallOptions("module firewall plan", args, false)
	if err != nil {
		return err
	}
	current, desired, client, node, err := loadFirewallContext(options.siteDir, options.ageIdentity)
	if err != nil {
		return err
	}
	status, statusErr := firewallmodule.ReadStatus(context.Background(), client, node, desired)
	fmt.Fprintln(out, "Firewall plan")
	if statusErr != nil || !status.Exists {
		fmt.Fprintf(out, "\nCreate:\n  provider %s\n  six LAB IPv4 gateways\n  reference zone firewall policy\n  ordinary Internet NAT\n", firewallmodule.ProviderName)
	} else {
		fmt.Fprintf(out, "\nPreserve:\n  provider %s (%s)\n", firewallmodule.ProviderName, firewallmodule.ProviderSummary(status))
		fmt.Fprintln(out, "  existing provider-native state outside Boetticher-owned sections")
		fmt.Fprintln(out, "Update if required:\n  six LAB IPv4 gateways\n  reference zone firewall policy\n  ordinary Internet NAT")
	}
	fmt.Fprintln(out, "\nPreserve:\n  Controller\n  Host enrollment and SSH trust\n  vmbr0\n  vmbr1\n  boetticher-data\n  physical networking")
	fmt.Fprintln(out, "\nDHCP: not configured\nDNS: not configured")
	_ = current
	return nil
}

func runFirewallApply(args []string, input io.Reader, out, errOut io.Writer) error {
	options, err := parseFirewallOptions("module firewall apply", args, false)
	if err != nil {
		return err
	}
	current, desired, client, node, err := loadFirewallContext(options.siteDir, options.ageIdentity)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	if err := firewallmodule.ValidateHostSubstrate(ctx, client, node); err != nil {
		return err
	}
	providerStatus, err := firewallmodule.ReadStatus(ctx, client, node, desired)
	if err != nil {
		return err
	}
	if !providerStatus.Exists && !options.yes {
		if input == nil {
			return errors.New("firewall apply requires --yes or an interactive confirmation")
		}
		answer, promptErr := promptYesNo(bufio.NewReader(input), out, "Create the firewall provider and change LAB routing? [y/N]: ", false)
		if promptErr != nil || !answer {
			if promptErr != nil {
				return promptErr
			}
			return errors.New("firewall apply cancelled")
		}
	}
	stateDir := firewallmodule.StateDir(current)
	credential := ""
	var image firewallmodule.Image
	bootstrapNeeded := !providerStatus.Exists || !providerStatus.StorageIdentity
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
		hash, hashErr := firewallmodule.PasswordHash(ctx, credential)
		if hashErr != nil {
			return hashErr
		}
		if bootstrapNeeded {
			builder := os.Getenv("BOETTICHER_OPENWRT_BUILDER")
			if builder == "" {
				builder = filepath.Join("scripts", "build-openwrt-firewall.sh")
			}
			image, err = firewallmodule.EnsureImage(ctx, firewallmodule.ImageSpec{CacheDir: filepath.Join(stateDir, "image-cache"), ManagementAddress: desired.ManagementAddress, PasswordHash: hash, BuilderScript: builder})
			if err != nil {
				return err
			}
		}
	}
	if bootstrapNeeded && image.Path == "" {
		hash, hashErr := firewallmodule.PasswordHash(ctx, credential)
		if hashErr != nil {
			return hashErr
		}
		builder := os.Getenv("BOETTICHER_OPENWRT_BUILDER")
		if builder == "" {
			builder = filepath.Join("scripts", "build-openwrt-firewall.sh")
		}
		image, err = firewallmodule.EnsureImage(ctx, firewallmodule.ImageSpec{CacheDir: filepath.Join(stateDir, "image-cache"), ManagementAddress: desired.ManagementAddress, PasswordHash: hash, BuilderScript: builder})
		if err != nil {
			return err
		}
	}
	if !providerStatus.Exists {
		fmt.Fprintf(out, "Firewall:\n  Provider: creating %s\n", firewallmodule.ProviderName)
	}
	result, err := firewallmodule.EnsureProvider(ctx, client, node, "boetticher-data", image)
	if err != nil {
		return err
	}
	trust, trustErr := firewallmodule.LoadTrust(stateDir)
	if errors.Is(trustErr, os.ErrNotExist) && bootstrapNeeded {
		trust, err = captureProviderTrust(ctx, desired.ManagementAddress)
		if err != nil {
			return err
		}
		if err := firewallmodule.StoreTrust(stateDir, trust); err != nil {
			return err
		}
	} else if trustErr != nil {
		return fmt.Errorf("load firewall provider TLS trust: %w", trustErr)
	}
	provider, err := openwrt.NewClient(openwrt.Config{BaseURL: "https://" + desired.ManagementAddress, Username: "boetticher", Password: credential, TrustPEM: trust})
	if err != nil {
		return err
	}
	if err := provider.Authenticate(ctx); err != nil {
		return err
	}
	networkCurrent, err := provider.UCIGet(ctx, "network")
	if err != nil {
		return err
	}
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
	runtimeInterfaces, err := provider.InterfaceDump(ctx)
	if err != nil {
		return fmt.Errorf("verify firewall provider runtime: %w", err)
	}
	if count := runtimeGatewayCount(runtimeInterfaces, desired); count != len(desired.Zones) {
		return fmt.Errorf("verify firewall provider runtime: %d/%d LAB gateways present", count, len(desired.Zones))
	}
	if !result.Changed && networkChanges == 0 && firewallChanges == 0 {
		fmt.Fprintln(out, "Firewall: No changes required.")
		return nil
	}
	fmt.Fprintf(out, "  Management: established\n  Network: applied (%d change(s))\n  Policy: applied (%d change(s))\n  Firewall: ready\n\nFirewall: PASS\n", networkChanges, firewallChanges)
	_ = errOut
	return nil
}

func runFirewallStatus(args []string, out io.Writer) error {
	options, err := parseFirewallOptions("module firewall status", args, false)
	if err != nil {
		return err
	}
	current, desired, client, node, err := loadFirewallContext(options.siteDir, options.ageIdentity)
	if err != nil {
		return err
	}
	status, err := firewallmodule.ReadStatus(context.Background(), client, node, desired)
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
	if err := provider.Authenticate(context.Background()); err != nil {
		return err
	}
	runtimeInterfaces, err := provider.InterfaceDump(context.Background())
	if err != nil {
		return err
	}
	gateways := runtimeGatewayCount(runtimeInterfaces, desired)
	if gateways != len(desired.Zones) {
		return fmt.Errorf("firewall status found %d/%d LAB gateways", gateways, len(desired.Zones))
	}
	fmt.Fprintf(out, "Firewall: PASS\nProvider: %s\nManagement: reachable\nGateways: %d/%d present\nFirewall: active\nInternet route: active\n", firewallmodule.ProviderSummary(status), gateways, len(desired.Zones))
	return nil
}

func runFirewallTeardown(args []string, input io.Reader, out, errOut io.Writer) error {
	options, err := parseFirewallOptions("module firewall teardown", args, true)
	if err != nil {
		return err
	}
	current, desired, client, node, err := loadFirewallContext(options.siteDir, options.ageIdentity)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	status, err := firewallmodule.ReadStatus(ctx, client, node, desired)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Firewall teardown will remove:\n  %s\n  its provider disk\n  Controller-owned provider credential and TLS trust\n\nIt will preserve:\n  Controller\n  Host\n  vmbr0\n  vmbr1\n  boetticher-data\n  physical networking\n", firewallmodule.ProviderName)
	if !options.yes {
		if input == nil {
			return errors.New("firewall teardown requires --yes or an interactive confirmation")
		}
		answer, promptErr := promptYesNo(bufio.NewReader(input), out, "Remove the firewall provider? [y/N]: ", false)
		if promptErr != nil || !answer {
			if promptErr != nil {
				return promptErr
			}
			return errors.New("firewall teardown cancelled")
		}
	}
	if status.Exists {
		if err := firewallmodule.DestroyProvider(ctx, client, node, "boetticher-data"); err != nil {
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

func captureProviderTrust(ctx context.Context, address string) ([]byte, error) {
	deadline := time.Now().Add(90 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		trust, err := openwrt.CaptureLeafCertificate(ctx, address)
		if err == nil {
			return trust, nil
		}
		last = err
		time.Sleep(2 * time.Second)
	}
	return nil, fmt.Errorf("provider TLS bootstrap timeout: %w", last)
}

func runtimeGatewayCount(runtime []byte, desired firewallmodule.DesiredState) int {
	count := 0
	for _, zone := range desired.Zones {
		if bytes.Contains(runtime, []byte("boetticher_iface_"+strings.ToLower(zone.Name))) {
			count++
		}
	}
	return count
}
