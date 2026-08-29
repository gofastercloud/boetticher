package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/gofastercloud/boetticher/internal/model"
	networkmodel "github.com/gofastercloud/boetticher/internal/network"
	"github.com/gofastercloud/boetticher/internal/proxmox"
	"github.com/gofastercloud/boetticher/internal/site"
)

func runInit(args []string, out interface{ Write([]byte) (int, error) }) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site-dir", model.DefaultSiteDir, "private site repository directory")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	externalFirewall := fs.Bool("external-firewall", false, "bring your own external firewall; do not create lab-fw-01")
	if err := fs.Parse(args); err != nil {
		return err
	}
	created, err := site.Init(*siteDir, *ageIdentity, *externalFirewall)
	if err != nil {
		return err
	}
	revision, _ := created.Revision()
	if err := writeModelProjections(*siteDir, created); err != nil {
		return err
	}
	if err := rebuildPortal(*siteDir, created); err != nil {
		return err
	}
	fmt.Fprintf(out, "Initialized private site repository: %s\n", *siteDir)
	fmt.Fprintf(out, "Age identity: %s (outside Git)\n", model.ExpandUserPath(*ageIdentity))
	fmt.Fprintf(out, "Model revision: %s\n", revision)
	fmt.Fprintf(out, "Gateway mode: %s\n", created.Gateway.Mode)
	fmt.Fprintf(out, "Gateway upstream MAC: %s (create the matching upstream DHCP reservation)\n", created.Gateway.Upstream.MAC)
	if created.Gateway.Mode == model.GatewayModeExternal {
		fmt.Fprintln(out, "External mode: a distinct physical vmbr1 trunk is required before bootstrap")
	}
	fmt.Fprintln(out, "Independent Age recovery copy: REQUIRED before destructive bootstrap")
	return nil
}

func runPreflight(args []string, out interface{ Write([]byte) (int, error) }) error {
	fs := flag.NewFlagSet("preflight", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	live := fs.Bool("live", false, "inspect the fresh Proxmox host over the recorded bootstrap path")
	record := fs.Bool("record", false, "persist approved physical discovery from --live")
	bootstrapAddress := fs.String("bootstrap-address", "", "fresh Proxmox HOME-side address when it is not yet recorded")
	initialUser := fs.String("initial-user", "root", "initial SSH user on the fresh Proxmox host")
	knownHosts := fs.String("known-hosts", "", "optional SSH known-hosts file for discovery")
	trunkInterface := fs.String("trunk-interface", "", "explicit trunk selection when multiple eligible NICs exist")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *record && !*live {
		return errors.New("--record requires --live; inspection is read-only without explicit recording")
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	if (runtime.GOOS != "darwin" && runtime.GOOS != "linux") || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		return fmt.Errorf("unsupported controller platform %s/%s; V1 supports macOS and Linux on amd64/arm64", runtime.GOOS, runtime.GOARCH)
	}
	if runtime.GOOS == "linux" && looksLikeProxmoxController("/") {
		return errors.New("boetticher V1 must run from a separate controller; run it from macOS or Linux, not on the target Proxmox host")
	}
	fmt.Fprintf(out, "Controller: PASS %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(out, "Gateway upstream MAC: %s (create the matching upstream DHCP reservation)\n", s.Gateway.Upstream.MAC)
	allPass := true
	for _, tool := range []string{"ssh", "ssh-keyscan", "age-keygen", "sops", "ansible", "ansible-playbook"} {
		path, err := exec.LookPath(tool)
		if err != nil {
			allPass = false
			fmt.Fprintf(out, "Tool %-12s FAIL missing\n", tool)
			continue
		}
		version := toolVersion(tool)
		if err := validateToolVersion(tool, version); err != nil {
			allPass = false
			fmt.Fprintf(out, "Tool %-12s FAIL %s (%s)\n", tool, err, version)
			continue
		}
		fmt.Fprintf(out, "Tool %-12s PASS %s (%s)\n", tool, path, version)
	}
	if !allPass {
		return fmt.Errorf("preflight failed: required tooling is missing")
	}
	if !*live {
		fmt.Fprintln(out, "Physical discovery: NOT TESTED (use --live after recording the HOME-side Proxmox address)")
		return nil
	}
	address := *bootstrapAddress
	if address == "" {
		address = s.BootstrapAddress
	}
	if address == "" {
		return errors.New("HOLD: upstream interface identity is ambiguous; set bootstrap-endpoint or pass --bootstrap-address")
	}
	runner := proxmox.SSHRunner{KnownHosts: *knownHosts, HostKeyAlias: model.LogicalProxmoxIdentity}
	discovered, err := proxmox.DiscoverPhysicalNetworkViaSSH(context.Background(), runner, address, *initialUser, address, s.PhysicalNetwork.Trunk.Name, *trunkInterface)
	if err != nil {
		return err
	}
	discovery := discovered.Discovery
	discovery = honorRequestedPhysicalMode(discovery, s.PhysicalNetwork.Mode, s.PhysicalNetwork.Trunk.Name, *trunkInterface)
	credentialsPath := filepath.Join(*siteDir, site.ProxmoxSecretsPath)
	credentialsExist, err := proxmoxCredentialsExist(credentialsPath)
	if err != nil {
		return fmt.Errorf("inspect existing Proxmox API credentials: %w", err)
	}
	if credentialsExist {
		credentials, err := site.LoadProxmoxCredentials(*siteDir, s, *ageIdentity)
		if err != nil {
			return fmt.Errorf("HOLD: load existing Proxmox API credentials: %w", err)
		}
		if credentials.APIUser != "labadmin@pve" || credentials.TokenID != "boetticher" {
			return fmt.Errorf("HOLD: encrypted Proxmox credentials identify %s!%s, expected labadmin@pve!boetticher", credentials.APIUser, credentials.TokenID)
		}
		if err := proxmox.CheckScopedCredentialReuse(context.Background(), runner, address, *initialUser, credentials.APIUser, credentials.TokenID, "BoetticherProvisioner"); err != nil {
			return err
		}
	} else if err := proxmox.CheckScopedCredentialAvailability(context.Background(), runner, address, *initialUser, "labadmin@pve", "boetticher", "BoetticherProvisioner"); err != nil {
		return err
	}
	fmt.Fprintf(out, "Proxmox node: PASS %s (discovered from /nodes)\n", discovered.Node)
	printPhysicalDiscovery(out, discovery)
	fmt.Fprintln(out, "Proxmox credential reservation: PASS")
	if discovery.Mode == networkmodel.ModeSelectionNeeded {
		return errors.New("HOLD: multiple eligible trunk interfaces require explicit selection")
	}
	if s.Gateway.Mode == model.GatewayModeExternal && discovery.Mode != networkmodel.ModePhysicalTrunk {
		return errors.New("external gateway mode requires a distinct physical vmbr1 trunk")
	}
	if *record {
		if err := writePhysicalDiscovery(*siteDir, s, discovery); err != nil {
			return err
		}
		if err := rebuildPortal(*siteDir, s); err != nil {
			return err
		}
		fmt.Fprintln(out, "Physical discovery: recorded with --live --record")
	} else {
		fmt.Fprintln(out, "Physical discovery: PASS (not persisted; use --live --record to approve recording)")
	}
	return nil
}

// looksLikeProxmoxController deliberately requires several independent local
// markers. A generic Linux controller must remain supported; only a host with
// the Proxmox cluster filesystem, cluster state directory, and pveversion
// executable is confidently identified as the target platform host.

func looksLikeProxmoxController(root string) bool {
	if !directoryExists(filepath.Join(root, "etc", "pve")) || !directoryExists(filepath.Join(root, "var", "lib", "pve-cluster")) {
		return false
	}
	pveversion, err := exec.LookPath("pveversion")
	if err != nil {
		return false
	}
	return looksLikeProxmoxControllerAt(root, pveversion)
}

func looksLikeProxmoxControllerAt(root, pveversion string) bool {
	return directoryExists(filepath.Join(root, "etc", "pve")) &&
		directoryExists(filepath.Join(root, "var", "lib", "pve-cluster")) &&
		fileExists(filepath.Join(root, strings.TrimPrefix(pveversion, "/")))
}

func directoryExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
