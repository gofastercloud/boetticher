package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/ansible"
	"github.com/gofastercloud/boetticher/internal/backup"
	"github.com/gofastercloud/boetticher/internal/dns"
	"github.com/gofastercloud/boetticher/internal/model"
	networkmodel "github.com/gofastercloud/boetticher/internal/network"
	"github.com/gofastercloud/boetticher/internal/opnsense"
	"github.com/gofastercloud/boetticher/internal/pki"
	"github.com/gofastercloud/boetticher/internal/portal"
	"github.com/gofastercloud/boetticher/internal/proxmox"
	"github.com/gofastercloud/boetticher/internal/site"
	"github.com/gofastercloud/boetticher/internal/sshconfig"
	"github.com/gofastercloud/boetticher/internal/zabbix"
)

func Run(args []string, out, errOut interface{ Write([]byte) (int, error) }) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		usage(out)
		return nil
	}
	switch args[0] {
	case "init":
		return runInit(args[1:], out)
	case "preflight":
		return runPreflight(args[1:], out)
	case "ssh-config":
		return runSSHConfig(args[1:], out)
	case "access":
		return runAccess(args[1:], out)
	case "portal":
		if len(args) > 1 && args[1] == "build" {
			return runPortalBuild(args[2:], out)
		}
	case "bootstrap-endpoint":
		return runBootstrapEndpoint(args[1:], out)
	case "pki":
		return runPKI(args[1:], out)
	case "opnsense":
		return runOPNsense(args[1:], out)
	case "network":
		return runNetwork(args[1:], out)
	case "verify":
		return runVerify(args[1:], out)
	case "doctor":
		return runDoctor(args[1:], out)
	case "bootstrap":
		return runBootstrap(args[1:], out)
	case "provision":
		return runProvision(args[1:], out)
	case "converge":
		return runConverge(args[1:], out)
	case "upgrade":
		return runIntegrationGate(args[0], args[1:], out)
	}
	fmt.Fprintf(errOut, "usage: boetticher <command>\n")
	return fmt.Errorf("unknown or incomplete command %q", strings.Join(args, " "))
}

func usage(out interface{ Write([]byte) (int, error) }) {
	fmt.Fprintln(out, "boetticher operator CLI\n\nUsage:")
	for _, spec := range commandSpecs {
		fmt.Fprintln(out, "  "+spec.Usage)
	}
}

func runInit(args []string, out interface{ Write([]byte) (int, error) }) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site-dir", model.DefaultSiteDir, "private site repository directory")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	created, err := site.Init(*siteDir, *ageIdentity)
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
	fmt.Fprintln(out, "Independent Age recovery copy: REQUIRED before destructive bootstrap")
	return nil
}

func runPreflight(args []string, out interface{ Write([]byte) (int, error) }) error {
	fs := flag.NewFlagSet("preflight", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	live := fs.Bool("live", false, "inspect the fresh Proxmox host over the recorded bootstrap path")
	bootstrapAddress := fs.String("bootstrap-address", "", "fresh Proxmox HOME-side address when it is not yet recorded")
	initialUser := fs.String("initial-user", "root", "initial SSH user on the fresh Proxmox host")
	knownHosts := fs.String("known-hosts", "", "optional SSH known-hosts file for discovery")
	trunkInterface := fs.String("trunk-interface", "", "explicit trunk selection when multiple eligible NICs exist")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	if (runtime.GOOS != "darwin" && runtime.GOOS != "linux") || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		return fmt.Errorf("unsupported controller platform %s/%s; V1 supports macOS and Linux on amd64/arm64", runtime.GOOS, runtime.GOARCH)
	}
	fmt.Fprintf(out, "Controller: PASS %s/%s\n", runtime.GOOS, runtime.GOARCH)
	allPass := true
	for _, tool := range []string{"git", "ssh", "ssh-keyscan", "age-keygen", "sops", "tofu", "ansible", "ansible-playbook"} {
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
	runner := proxmox.SSHRunner{KnownHosts: *knownHosts}
	discovery, err := proxmox.DiscoverPhysicalNetworkViaSSH(context.Background(), runner, address, *initialUser, s.ProxmoxNode, address, s.PhysicalNetwork.Trunk.Name, *trunkInterface)
	if err != nil {
		return err
	}
	printPhysicalDiscovery(out, discovery)
	if err := writePhysicalDiscovery(*siteDir, s, discovery); err != nil {
		return err
	}
	if err := rebuildPortal(*siteDir, s); err != nil {
		return err
	}
	if discovery.Mode == networkmodel.ModeSelectionNeeded {
		return errors.New("HOLD: multiple eligible trunk interfaces require explicit selection")
	}
	fmt.Fprintf(out, "Physical discovery: PASS %s\n", discovery.Mode)
	return nil
}

func runSSHConfig(args []string, out interface{ Write([]byte) (int, error) }) error {
	fs := flag.NewFlagSet("ssh-config", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	output := fs.String("output", sshconfig.DefaultPath(), "output path, or - for stdout")
	force := fs.Bool("force", false, "overwrite an existing output")
	check := fs.Bool("check", false, "validate an existing configuration")
	identity := fs.String("identity-file", "", "operator SSH identity file")
	installInclude := fs.Bool("install-include", false, "explicitly add the config.d include to ~/.ssh/config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	if *identity != "" {
		s.SSHIdentityFile = *identity
	}
	if *check {
		if err := sshconfig.Check(*output, s); err != nil {
			return err
		}
		fmt.Fprintln(out, "SSH configuration: PASS current and model-consistent")
		return nil
	}
	content, err := sshconfig.Render(s, time.Now())
	if err != nil {
		return err
	}
	if *output == "-" {
		_, err = out.Write([]byte(content))
	} else {
		err = sshconfig.Write(*output, []byte(content), *force)
		if err == nil {
			fmt.Fprintf(out, "Generated SSH configuration: %s\n", model.ExpandUserPath(*output))
		}
	}
	if err != nil {
		return err
	}
	if *installInclude {
		if *output == "-" {
			return fmt.Errorf("--install-include requires a file output")
		}
		if err := installSSHInclude(); err != nil {
			return err
		}
		fmt.Fprintln(out, "Installed explicit ~/.ssh/config include")
	}
	if *output != "-" {
		if err := writeAccessProjection(*siteDir, s); err != nil {
			return err
		}
	}
	return nil
}

func runAccess(args []string, out interface{ Write([]byte) (int, error) }) error {
	fs := flag.NewFlagSet("access", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "Bootstrap")
	if s.BootstrapAddress == "" {
		fmt.Fprintln(out, "  Proxmox       bootstrap endpoint not configured")
	} else {
		fmt.Fprintf(out, "  Proxmox       ssh proxmox\n                https://%s:8006\n", s.BootstrapAddress)
	}
	fmt.Fprintln(out, "Internal SSH")
	for _, m := range sortedSSHModules(s) {
		alias := m.Name
		if len(m.DNSAliases) > 0 {
			alias = m.DNSAliases[0]
		}
		fmt.Fprintf(out, "  %-13s ssh %s\n", m.Role, alias)
	}
	fmt.Fprintln(out, "Web")
	for _, m := range s.Modules {
		if m.URL != "" {
			fmt.Fprintf(out, "  %-13s %s\n", m.Role, m.URL)
		}
	}
	fmt.Fprintln(out, "Access path")
	fmt.Fprintln(out, "  Internal SSH  via Proxmox bastion")
	if s.PhysicalNetwork.Mode == model.ModeVirtualOnly {
		fmt.Fprintln(out, "  Physical lab  virtual-only")
	} else {
		fmt.Fprintf(out, "  Physical lab  %s attached\n", s.PhysicalNetwork.Trunk.Name)
	}
	fmt.Fprintln(out, "  Remote access not configured")
	return nil
}

func runPortalBuild(args []string, out interface{ Write([]byte) (int, error) }) error {
	fs := flag.NewFlagSet("portal build", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	output := fs.String("output", "", "portal output directory")
	docsDir := fs.String("docs", "docs", "product documentation directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	if *output == "" {
		*output = filepath.Join(*siteDir, "generated", "portal")
	}
	revision, err := s.Revision()
	if err != nil {
		return err
	}
	evidence := loadEvidence(*siteDir, revision)
	if err := portal.Build(s, *output, *docsDir, evidence, loadPhysicalDiscovery(*siteDir, s), time.Now()); err != nil {
		return err
	}
	if err := writeModelProjections(*siteDir, s); err != nil {
		return err
	}
	fmt.Fprintf(out, "Generated passive portal: %s\n", *output)
	return nil
}

func runBootstrapEndpoint(args []string, out interface{ Write([]byte) (int, error) }) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: boetticher bootstrap-endpoint show|set ADDRESS [--site DIR]")
	}
	command := args[0]
	fs := flag.NewFlagSet("bootstrap-endpoint", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	if command == "set" {
		if len(args) < 2 {
			return fmt.Errorf("bootstrap endpoint address is required")
		}
		address := args[1]
		if err := sshconfig.ValidateBootstrapAddress(address); err != nil {
			return err
		}
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		s, err := site.Load(*siteDir)
		if err != nil {
			return err
		}
		s.BootstrapAddress = net.ParseIP(address).To4().String()
		if err := site.Save(*siteDir, s); err != nil {
			return err
		}
		if err := writeModelProjections(*siteDir, s); err != nil {
			return err
		}
		if err := rebuildPortal(*siteDir, s); err != nil {
			return err
		}
		fmt.Fprintf(out, "Recorded upstream Proxmox bootstrap address: %s\n", s.BootstrapAddress)
		return nil
	}
	if command != "show" {
		return fmt.Errorf("unknown bootstrap-endpoint command %q", command)
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	if s.BootstrapAddress == "" {
		fmt.Fprintln(out, "Bootstrap endpoint: NOT CONFIGURED")
	} else {
		fmt.Fprintf(out, "Bootstrap endpoint: %s\n", s.BootstrapAddress)
	}
	return nil
}

func runPKI(args []string, out interface{ Write([]byte) (int, error) }) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: boetticher pki client create|export|revoke NAME; boetticher pki trust export")
	}
	subcommand := args[0]
	if subcommand == "trust" && args[1] == "export" {
		return runPKITrust(args[2:], out)
	}
	if subcommand != "client" {
		return fmt.Errorf("unknown pki command %q", subcommand)
	}
	if len(args) < 3 {
		return fmt.Errorf("client name is required")
	}
	command, name := args[1], args[2]
	fs := flag.NewFlagSet("pki client", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	output := fs.String("output", "", "export output path")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	if err := fs.Parse(args[3:]); err != nil {
		return err
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	runtimeDir := filepath.Join(site.RuntimeDir(s), "pki", name)
	switch command {
	case "create":
		authority, err := site.LoadAuthority(*siteDir, s, *ageIdentity)
		if err != nil {
			return err
		}
		certificate, err := pki.IssueClient(authority, name, s.Network.Domain, time.Now().UTC())
		if err != nil {
			return err
		}
		if err := os.MkdirAll(runtimeDir, 0700); err != nil {
			return err
		}
		if err := writePrivate(filepath.Join(runtimeDir, "client.key.pem"), []byte(certificate.KeyPEM)); err != nil {
			return err
		}
		if err := writePublic(filepath.Join(runtimeDir, "client.crt.pem"), []byte(certificate.CertPEM)); err != nil {
			return err
		}
		if err := writePublic(filepath.Join(runtimeDir, "chain.crt.pem"), []byte(certificate.ChainPEM)); err != nil {
			return err
		}
		metadata := fmt.Sprintf("name: %s\nfingerprint: %s\ncreated_at: %s\n", name, certificate.Fingerprint, time.Now().UTC().Format(time.RFC3339))
		if err := writePublic(filepath.Join(*siteDir, "generated", "pki", name+".yaml"), []byte(metadata)); err != nil {
			return err
		}
		if s.BootstrapAddress != "" {
			if err := rebuildPortal(*siteDir, s); err != nil {
				return err
			}
		}
		fmt.Fprintf(out, "Created client certificate %s\nPrivate key: %s\nCertificate: %s\n", name, filepath.Join(runtimeDir, "client.key.pem"), filepath.Join(runtimeDir, "client.crt.pem"))
		return nil
	case "export":
		return exportClient(runtimeDir, *output, out)
	case "revoke":
		return revokeClient(*siteDir, name, out)
	default:
		return fmt.Errorf("unknown pki client command %q", command)
	}
}

func exportClient(runtimeDir, output string, out interface{ Write([]byte) (int, error) }) error {
	key, err := os.ReadFile(filepath.Join(runtimeDir, "client.key.pem"))
	if err != nil {
		return fmt.Errorf("read client private key: %w", err)
	}
	cert, err := os.ReadFile(filepath.Join(runtimeDir, "chain.crt.pem"))
	if err != nil {
		return fmt.Errorf("read client certificate chain: %w", err)
	}
	if output == "" {
		output = filepath.Join(runtimeDir, "client-bundle.pem")
	}
	if output == "-" {
		return fmt.Errorf("refusing to write a client private key to stdout; choose a file output")
	}
	if err := writePrivate(output, append(key, cert...)); err != nil {
		return err
	}
	fmt.Fprintf(out, "Exported client PEM bundle: %s\n", output)
	return nil
}

func revokeClient(siteDir, name string, out interface{ Write([]byte) (int, error) }) error {
	if err := pki.ValidateClientName(name); err != nil {
		return err
	}
	revocation := fmt.Sprintf("name: %s\nstatus: revoked\nrevoked_at: %s\n", name, time.Now().UTC().Format(time.RFC3339))
	path := filepath.Join(siteDir, "generated", "pki", "revoked", name+".yaml")
	if err := writePublic(path, []byte(revocation)); err != nil {
		return err
	}
	if s, err := site.Load(siteDir); err == nil && s.BootstrapAddress != "" {
		if err := rebuildPortal(siteDir, s); err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "Recorded client revocation: %s\n", name)
	return nil
}

func runPKITrust(args []string, out interface{ Write([]byte) (int, error) }) error {
	fs := flag.NewFlagSet("pki trust export", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	output := fs.String("output", "-", "output path, or - for stdout")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	authority, err := site.LoadAuthority(*siteDir, s, *ageIdentity)
	if err != nil {
		return err
	}
	content := []byte(authority.RootCertPEM + authority.IssuingCertPEM)
	if *output == "-" {
		_, err = out.Write(content)
		return err
	}
	if err := writePublic(*output, content); err != nil {
		return err
	}
	fmt.Fprintf(out, "Exported trust chain: %s\n", *output)
	return nil
}

func runOPNsense(args []string, out interface{ Write([]byte) (int, error) }) error {
	if len(args) < 2 || args[0] != "credentials" || args[1] != "import" {
		return errors.New("usage: boetticher opnsense credentials import [--site DIR] < credentials.json")
	}
	fs := flag.NewFlagSet("opnsense credentials import", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	if err := fs.Parse(args[2:]); err != nil {
		return err
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, 64<<10))
	if err != nil {
		return fmt.Errorf("read OPNsense credential input: %w", err)
	}
	var credentials site.OPNsenseCredentials
	if err := json.Unmarshal(data, &credentials); err != nil {
		return errors.New("OPNsense credential input must be a JSON object with api_key and api_secret")
	}
	if err := site.StoreOPNsenseCredentials(*siteDir, s, credentials); err != nil {
		return err
	}
	if s.BootstrapAddress != "" {
		if err := rebuildPortal(*siteDir, s); err != nil {
			return err
		}
	}
	fmt.Fprintln(out, "Stored OPNsense API credentials in encrypted SOPS state")
	return nil
}

func runNetwork(args []string, out interface{ Write([]byte) (int, error) }) error {
	if len(args) < 2 || args[0] != "trunk" {
		return fmt.Errorf("usage: boetticher network trunk status|attach|detach [--site DIR]")
	}
	command := args[1]
	rest := args[2:]
	interfaceName := ""
	if (command == "attach" || command == "detach") && len(rest) > 0 && !strings.HasPrefix(rest[0], "--") {
		interfaceName = rest[0]
		rest = rest[1:]
	}
	fs := flag.NewFlagSet("network trunk", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	confirm := fs.Bool("confirm", false, "confirm a live network change")
	live := fs.Bool("live", false, "inspect the Proxmox node instead of only the site model")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	proxmoxCA := fs.String("proxmox-ca", "", "Proxmox API CA PEM file")
	insecure := fs.Bool("insecure", false, "explicitly allow self-signed Proxmox API TLS")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	switch command {
	case "status":
		if s.PhysicalNetwork.Mode == model.ModeVirtualOnly {
			fmt.Fprintln(out, "Physical trunk: virtual-only")
		} else {
			fmt.Fprintf(out, "Physical trunk: %s attached\n", s.PhysicalNetwork.Trunk.Name)
		}
		if !*live {
			return nil
		}
		client, _, err := loadProxmoxClient(*siteDir, s, *ageIdentity, *proxmoxCA, *insecure)
		if err != nil {
			return err
		}
		var interfaces []proxmox.NetworkInterface
		if err := client.NodeNetwork(context.Background(), s.ProxmoxNode, &interfaces); err != nil {
			return err
		}
		discovery, err := proxmox.DiscoverPhysicalNetwork(context.Background(), client, s.ProxmoxNode, s.BootstrapAddress, s.PhysicalNetwork.Trunk.Name)
		if err != nil {
			return err
		}
		printPhysicalDiscovery(out, discovery)
		for _, iface := range interfaces {
			if iface.Iface == "vmbr1" {
				fmt.Fprintf(out, "vmbr1: PASS bridge ports=%s vlan-aware=%t\n", iface.BridgePorts, iface.BridgeVLANAware)
				return nil
			}
		}
		return errors.New("vmbr1 is absent on Proxmox")
	case "attach", "detach":
		if interfaceName == "" {
			return fmt.Errorf("network trunk %s requires an interface name", command)
		}
		if s.BootstrapAddress == "" {
			return fmt.Errorf("cannot prove the interface is not the HOME/bootstrap path until bootstrap-endpoint is set")
		}
		client, _, err := loadProxmoxClient(*siteDir, s, *ageIdentity, *proxmoxCA, *insecure)
		if err != nil {
			return err
		}
		ctx := context.Background()
		var observedDiscovery *networkmodel.Discovery
		if command == "attach" {
			discovery, discoveryErr := proxmox.DiscoverPhysicalNetworkWithSelection(ctx, client, s.ProxmoxNode, s.BootstrapAddress, s.PhysicalNetwork.Trunk.Name, interfaceName)
			if discoveryErr != nil {
				return discoveryErr
			}
			observedDiscovery = &discovery
			printPhysicalDiscovery(out, discovery)
			if !*confirm {
				return fmt.Errorf("network trunk attach is a potentially locking live change; review the proposal and repeat with --confirm")
			}
			if err := proxmox.AttachTrunk(ctx, client, s.ProxmoxNode, interfaceName, s.BootstrapAddress); err != nil {
				return err
			}
			s.PhysicalNetwork.Mode = model.ModePhysicalTrunk
			s.PhysicalNetwork.Trunk.Name = interfaceName
			if discovery.Trunk != nil {
				s.PhysicalNetwork.Trunk.PermanentMAC = discovery.Trunk.PermanentMAC
				s.PhysicalNetwork.Trunk.PCIAddress = discovery.Trunk.PCIAddress
			}
			if discovery.Upstream.Name != "" {
				s.PhysicalNetwork.Upstream = model.PhysicalNIC{Name: discovery.Upstream.Name, PermanentMAC: discovery.Upstream.PermanentMAC, PCIAddress: discovery.Upstream.PCIAddress}
			}
			var after []proxmox.NetworkInterface
			if err := client.NodeNetwork(ctx, s.ProxmoxNode, &after); err != nil {
				return rollbackTrunkChange(ctx, client, s.ProxmoxNode, interfaceName, s.BootstrapAddress, "HOLD: trunk attach could not be re-read", err)
			}
			if _, err := proxmox.ValidatePhysicalBinding(s, after); err != nil {
				return rollbackTrunkChange(ctx, client, s.ProxmoxNode, interfaceName, s.BootstrapAddress, "HOLD: trunk attach failed post-change validation", err)
			}
			postDiscovery, err := proxmox.AnalyzePhysicalNetwork(after, s.BootstrapAddress, interfaceName)
			if err != nil {
				return rollbackTrunkChange(ctx, client, s.ProxmoxNode, interfaceName, s.BootstrapAddress, "HOLD: trunk attach produced ambiguous physical evidence", err)
			}
			observedDiscovery = &postDiscovery
		} else {
			if s.PhysicalNetwork.Trunk.Name != interfaceName {
				return fmt.Errorf("site records physical trunk %q, not %q", s.PhysicalNetwork.Trunk.Name, interfaceName)
			}
			if !*confirm {
				return fmt.Errorf("network trunk detach is a potentially locking live change; repeat with --confirm")
			}
			if err := proxmox.DetachTrunk(ctx, client, s.ProxmoxNode, interfaceName, s.BootstrapAddress); err != nil {
				return err
			}
			s.PhysicalNetwork.Mode = model.ModeVirtualOnly
			s.PhysicalNetwork.Trunk = model.PhysicalNIC{}
			var after []proxmox.NetworkInterface
			if err := client.NodeNetwork(ctx, s.ProxmoxNode, &after); err != nil {
				return rollbackDetachedTrunkChange(ctx, client, s.ProxmoxNode, interfaceName, s.BootstrapAddress, "HOLD: trunk detach could not be re-read", err)
			}
			if _, err := proxmox.ValidatePhysicalBinding(s, after); err != nil {
				return rollbackDetachedTrunkChange(ctx, client, s.ProxmoxNode, interfaceName, s.BootstrapAddress, "HOLD: trunk detach failed post-change validation", err)
			}
			postDiscovery, err := proxmox.AnalyzePhysicalNetwork(after, s.BootstrapAddress, "")
			if err != nil {
				return rollbackDetachedTrunkChange(ctx, client, s.ProxmoxNode, interfaceName, s.BootstrapAddress, "HOLD: trunk detach produced ambiguous physical evidence", err)
			}
			observedDiscovery = &postDiscovery
		}
		if err := site.Save(*siteDir, s); err != nil {
			return fmt.Errorf("HOLD: trunk changed but physical binding could not be persisted: %w", err)
		}
		if err := writeModelProjections(*siteDir, s); err != nil {
			return fmt.Errorf("HOLD: trunk changed but projections could not be regenerated: %w", err)
		}
		if observedDiscovery != nil {
			if err := writePhysicalDiscovery(*siteDir, s, *observedDiscovery); err != nil {
				return fmt.Errorf("HOLD: trunk changed but physical evidence could not be written: %w", err)
			}
		}
		if err := rebuildPortal(*siteDir, s); err != nil {
			return fmt.Errorf("HOLD: trunk changed but portal could not be regenerated: %w", err)
		}
		fmt.Fprintf(out, "Physical trunk: PASS %s %s vmbr1\n", command, interfaceName)
		return nil
	default:
		return fmt.Errorf("unknown trunk command %q", command)
	}
}

func rollbackTrunkChange(ctx context.Context, client *proxmox.Client, node, interfaceName, bootstrapAddress, message string, cause error) error {
	if rollbackErr := proxmox.DetachTrunk(ctx, client, node, interfaceName, bootstrapAddress); rollbackErr != nil {
		return fmt.Errorf("%s and rollback failed: %v; cause: %w", message, rollbackErr, cause)
	}
	return fmt.Errorf("%s; rollback completed: %w", message, cause)
}

func rollbackDetachedTrunkChange(ctx context.Context, client *proxmox.Client, node, interfaceName, bootstrapAddress, message string, cause error) error {
	if rollbackErr := proxmox.AttachTrunk(ctx, client, node, interfaceName, bootstrapAddress); rollbackErr != nil {
		return fmt.Errorf("%s and rollback failed: %v; cause: %w", message, rollbackErr, cause)
	}
	return fmt.Errorf("%s; rollback completed: %w", message, cause)
}

func printPhysicalDiscovery(out interface{ Write([]byte) (int, error) }, discovery networkmodel.Discovery) {
	fmt.Fprintf(out, "Detected network topology\nUpstream/bootstrap\n  %s\n  address: %s\n  model: %s\n  permanent MAC: %s\n  PCI: %s\n  driver: %s\n  speed: %s\n  carrier: %t\n", discovery.Upstream.Name, valueOrUnknown(discovery.BootstrapAddress), valueOrUnknown(discovery.Upstream.Model), valueOrUnknown(discovery.Upstream.PermanentMAC), valueOrUnknown(discovery.Upstream.PCIAddress), valueOrUnknown(discovery.Upstream.Driver), speedText(discovery.Upstream.SpeedMbps), discovery.Upstream.Carrier)
	if discovery.Mode == networkmodel.ModeSelectionNeeded {
		fmt.Fprintln(out, "Eligible internal trunk interfaces")
		for index, candidate := range discovery.Candidates {
			fmt.Fprintf(out, "  [%d] %s - %s - MAC %s - %s - carrier %t\n", index+1, candidate.Name, valueOrUnknown(candidate.Model), valueOrUnknown(candidate.PermanentMAC), speedText(candidate.SpeedMbps), candidate.Carrier)
		}
		fmt.Fprintln(out, "Select the internal trunk interface with --trunk-interface or the command-specific interface argument.")
	} else if discovery.Trunk != nil {
		fmt.Fprintf(out, "Internal trunk candidate\n  %s\n  model: %s\n  permanent MAC: %s\n  PCI: %s\n  driver: %s\n  speed: %s\n  carrier: %t\n", discovery.Trunk.Name, valueOrUnknown(discovery.Trunk.Model), valueOrUnknown(discovery.Trunk.PermanentMAC), valueOrUnknown(discovery.Trunk.PCIAddress), valueOrUnknown(discovery.Trunk.Driver), speedText(discovery.Trunk.SpeedMbps), discovery.Trunk.Carrier)
	}
	fmt.Fprintf(out, "Proposed platform mapping\n  vmbr0 -> %s\n  vmbr1 -> %s\n  mode: %s\n", discovery.Upstream.Name, trunkName(discovery), discovery.Mode)
}

func trunkName(discovery networkmodel.Discovery) string {
	if discovery.Trunk == nil {
		return "none"
	}
	return discovery.Trunk.Name
}

func valueOrUnknown(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}

func speedText(speedMbps int) string {
	if speedMbps <= 0 {
		return "unknown"
	}
	if speedMbps >= 1000 && speedMbps%1000 == 0 {
		return fmt.Sprintf("%d Gb/s", speedMbps/1000)
	}
	return fmt.Sprintf("%d Mb/s", speedMbps)
}

func runVerify(args []string, out interface{ Write([]byte) (int, error) }) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	sshPath := fs.String("ssh-config", sshconfig.DefaultPath(), "generated SSH configuration to inspect")
	sshJourney := fs.Bool("ssh-journey", false, "run an authenticated internal SSH journey through the bastion")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	revision, err := s.Revision()
	if err != nil {
		return err
	}
	sshResult := portal.CheckResult{Name: "generated SSH configuration", Status: "NOT TESTED", Detail: "run boetticher ssh-config first"}
	if err := sshconfig.Check(*sshPath, s); err == nil {
		sshResult = portal.CheckResult{Name: "generated SSH configuration", Status: "PASS", Detail: "configuration is current and preserves host-key verification"}
	} else if !errors.Is(err, os.ErrNotExist) && !strings.Contains(err.Error(), "no such file") {
		sshResult = portal.CheckResult{Name: "generated SSH configuration", Status: "FAIL", Detail: err.Error()}
	}
	sshJourneyResult := portal.CheckResult{Name: "authenticated SSH journey via Proxmox bastion", Status: "NOT TESTED", Detail: "use --ssh-journey to exercise an internal host"}
	if *sshJourney {
		if sshResult.Status != "PASS" {
			sshJourneyResult.Detail = "generated SSH configuration is not current"
		} else if err := runSSHJourney(*sshPath); err != nil {
			sshJourneyResult = portal.CheckResult{Name: "authenticated SSH journey via Proxmox bastion", Status: "FAIL", Detail: err.Error()}
		} else {
			sshJourneyResult = portal.CheckResult{Name: "authenticated SSH journey via Proxmox bastion", Status: "PASS", Detail: "authenticated command completed through ProxyJump"}
		}
	}
	evidence := portal.Evidence{GeneratedAt: time.Now().UTC().Format(time.RFC3339), Results: []portal.CheckResult{
		{Name: "canonical platform model validates", Status: "PASS", Detail: "fixed V1 topology and address contract validated locally"},
		sshResult,
		sshJourneyResult,
		{Name: "DNS01/DNS02 reachable", Status: "NOT TESTED", Detail: "requires deployed network journey"},
		{Name: "NTP01/NTP02 synchronized", Status: "NOT TESTED", Detail: "requires deployed Chrony evidence"},
		{Name: "OPNsense API least privilege", Status: "NOT TESTED", Detail: "requires authenticated OPNsense API evidence"},
		{Name: "Proxmox API least privilege", Status: "NOT TESTED", Detail: "requires authenticated Proxmox API evidence"},
		{Name: "internal CA available", Status: "PASS", Detail: "CA metadata is present in the initialized model"},
		{Name: "SANDBOX cannot access TRUSTED", Status: "NOT TESTED", Detail: "requires virtual-lab or live network journey"},
		{Name: "SANDBOX cannot access SERVERS", Status: "NOT TESTED", Detail: "requires virtual-lab or live network journey"},
		{Name: "SANDBOX cannot access MGMT", Status: "NOT TESTED", Detail: "requires virtual-lab or live network journey"},
		{Name: "MGMT DHCP is reservation-only", Status: "NOT TESTED", Detail: "requires authenticated OPNsense API evidence"},
		{Name: "portal requires client certificate", Status: "NOT TESTED", Detail: "requires deployed mTLS journey"},
		{Name: "Zabbix requires client certificate", Status: "NOT TESTED", Detail: "requires deployed mTLS journey"},
		{Name: "latest VM/LXC backup", Status: "NOT TESTED", Detail: "requires current backup evidence"},
		{Name: "Age recovery fixture", Status: "NOT TESTED", Detail: "requires independent recovery copy"},
	}}
	document := struct {
		ModelRevision string          `json:"model_revision"`
		Evidence      portal.Evidence `json:"evidence"`
	}{ModelRevision: revision, Evidence: evidence}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	if err := writePublic(filepath.Join(*siteDir, "generated", "verification.json"), append(data, '\n')); err != nil {
		return err
	}
	overall := "HEALTHY"
	for _, result := range evidence.Results {
		if result.Status == "FAIL" {
			overall = "FAIL"
			break
		}
		if result.Status == "NOT TESTED" || result.Status == "HOLD" || result.Status == "INCONCLUSIVE" {
			overall = "PARTIAL"
		}
	}
	if err := writeProjection(filepath.Join(*siteDir, "generated", "status.json"), struct {
		ModelRevision string `json:"model_revision"`
		Status        string `json:"status"`
		GeneratedAt   string `json:"generated_at"`
	}{revision, overall, evidence.GeneratedAt}); err != nil {
		return err
	}
	if s.BootstrapAddress != "" {
		if err := rebuildPortal(*siteDir, s); err != nil {
			return err
		}
	}
	for _, result := range evidence.Results {
		fmt.Fprintf(out, "%-48s %s\n", result.Name, result.Status)
	}
	fmt.Fprintf(out, "Model revision: %s\n", revision)
	for _, result := range evidence.Results {
		if result.Status == "FAIL" {
			return errors.New("verification found a failed local check")
		}
	}
	return nil
}

func runDoctor(args []string, out interface{ Write([]byte) (int, error) }) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	sshPath := fs.String("ssh-config", sshconfig.DefaultPath(), "generated SSH configuration to check")
	live := fs.Bool("live", false, "perform bounded endpoint and SSH host-key checks")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	proxmoxCA := fs.String("proxmox-ca", "", "Proxmox API CA PEM file")
	insecure := fs.Bool("insecure", false, "explicitly allow self-signed Proxmox API TLS")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	revision, err := s.Revision()
	if err != nil {
		return err
	}
	checks := []struct {
		name  string
		path  string
		check func() error
	}{
		{"model projection", filepath.Join(*siteDir, "generated", "model.json"), func() error { return checkRevisionFile(filepath.Join(*siteDir, "generated", "model.json"), revision) }},
		{"status artifact", filepath.Join(*siteDir, "generated", "status.json"), func() error { return checkRevisionFile(filepath.Join(*siteDir, "generated", "status.json"), revision) }},
		{"inventory projection", filepath.Join(*siteDir, "generated", "inventory.json"), func() error {
			return checkRevisionFile(filepath.Join(*siteDir, "generated", "inventory.json"), revision)
		}},
		{"OPNsense policy", filepath.Join(*siteDir, "generated", "opnsense", "desired-policy.json"), func() error {
			return checkRevisionFile(filepath.Join(*siteDir, "generated", "opnsense", "desired-policy.json"), revision)
		}},
		{"OPNsense bootstrap", filepath.Join(*siteDir, "generated", "opnsense", "bootstrap.json"), func() error {
			return checkRevisionFile(filepath.Join(*siteDir, "generated", "opnsense", "bootstrap.json"), revision)
		}},
		{"DNS/DDNS policy", filepath.Join(*siteDir, "generated", "dns", "desired-state.json"), func() error {
			return checkRevisionFile(filepath.Join(*siteDir, "generated", "dns", "desired-state.json"), revision)
		}},
		{"physical discovery", filepath.Join(*siteDir, "generated", "network", "physical.json"), func() error {
			return checkRevisionFile(filepath.Join(*siteDir, "generated", "network", "physical.json"), revision)
		}},
		{"backup policy", filepath.Join(*siteDir, "generated", "backup", "desired-policy.json"), func() error {
			return checkRevisionFile(filepath.Join(*siteDir, "generated", "backup", "desired-policy.json"), revision)
		}},
		{"Proxmox desired state", filepath.Join(*siteDir, "generated", "proxmox", "desired-state.json"), func() error {
			return checkRevisionFile(filepath.Join(*siteDir, "generated", "proxmox", "desired-state.json"), revision)
		}},
		{"Zabbix provisioning", filepath.Join(*siteDir, "generated", "zabbix", "provisioning.json"), func() error {
			return checkRevisionFile(filepath.Join(*siteDir, "generated", "zabbix", "provisioning.json"), revision)
		}},
		{"Ansible inventory", filepath.Join(*siteDir, "generated", "ansible", "inventory.ini"), func() error {
			return checkRevisionFile(filepath.Join(*siteDir, "generated", "ansible", "inventory.ini"), revision)
		}},
		{"bastion policy", filepath.Join(*siteDir, "generated", "ssh", "lab-jump.conf"), func() error {
			return checkRevisionFile(filepath.Join(*siteDir, "generated", "ssh", "lab-jump.conf"), revision)
		}},
		{"SSH projection", filepath.Join(*siteDir, "generated", "ssh", "boetticher.conf"), func() error {
			return checkRevisionFile(filepath.Join(*siteDir, "generated", "ssh", "boetticher.conf"), revision)
		}},
		{"verification evidence", filepath.Join(*siteDir, "generated", "verification.json"), func() error {
			return checkRevisionFile(filepath.Join(*siteDir, "generated", "verification.json"), revision)
		}},
		{"portal", filepath.Join(*siteDir, "generated", "portal", "index.html"), func() error {
			return checkRevisionFile(filepath.Join(*siteDir, "generated", "portal", "index.html"), revision)
		}},
		{"SSH configuration", *sshPath, func() error { return sshconfig.Check(*sshPath, s) }},
	}
	failed := false
	for _, check := range checks {
		if err := check.check(); err != nil {
			failed = true
			if errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "no such file") {
				fmt.Fprintf(out, "%-22s ABSENT (%s)\n", check.name, check.path)
			} else {
				fmt.Fprintf(out, "%-22s INCONSISTENT (%v)\n", check.name, err)
			}
		} else {
			fmt.Fprintf(out, "%-22s CURRENT\n", check.name)
		}
	}
	if s.PhysicalNetwork.Mode == model.ModeVirtualOnly {
		fmt.Fprintln(out, "Physical trunk        NOTICE virtual-only")
	} else {
		fmt.Fprintf(out, "Physical trunk        PASS %s attached\n", s.PhysicalNetwork.Trunk.Name)
	}
	fmt.Fprintln(out, "OPNsense bootstrap    HOLD exact unattended installer/interface/API sequence requires fresh-host qualification")
	if s.BootstrapAddress == "" {
		fmt.Fprintln(out, "Bootstrap endpoint    ABSENT (record the HOME-side Proxmox address)")
	} else if !*live {
		fmt.Fprintf(out, "Bootstrap endpoint    NOT TESTED %s (use --live)\n", s.BootstrapAddress)
	} else if err := checkBootstrapEndpoint(*siteDir, s); err != nil {
		failed = true
		fmt.Fprintf(out, "Bootstrap endpoint    FAIL %v\n", err)
	} else {
		fmt.Fprintf(out, "Bootstrap endpoint    PASS %s and SSH host key\n", s.BootstrapAddress)
	}
	if *live {
		plan, planErr := proxmox.PlanFromSite(s)
		if planErr != nil {
			failed = true
			fmt.Fprintf(out, "Platform guests       FAIL invalid platform plan: %v\n", planErr)
		} else if client, _, clientErr := loadProxmoxClient(*siteDir, s, *ageIdentity, *proxmoxCA, *insecure); clientErr != nil {
			fmt.Fprintf(out, "Platform guests       NOT TESTED (%v)\n", clientErr)
		} else if audits, auditErr := proxmox.AuditGuests(context.Background(), client, plan); auditErr != nil {
			failed = true
			fmt.Fprintf(out, "Platform guests       FAIL %v\n", auditErr)
		} else {
			userCount := 0
			for _, audit := range audits {
				if audit.Ownership == proxmox.UserOwnership {
					userCount++
					continue
				}
				fmt.Fprintf(out, "Platform guest %-8d %-18s %s\n", audit.VMID, audit.Name, audit.Result)
				if audit.Result == "DRIFT" || audit.Result == "MISSING" {
					failed = true
				}
			}
			if userCount > 0 {
				fmt.Fprintf(out, "User-managed guests  INFO %d additional Proxmox guests detected; outside boetticher ownership\n", userCount)
			} else {
				fmt.Fprintln(out, "User-managed guests  INFO none detected")
			}
			var interfaces []proxmox.NetworkInterface
			if networkErr := client.NodeNetwork(context.Background(), s.ProxmoxNode, &interfaces); networkErr != nil {
				failed = true
				fmt.Fprintf(out, "Physical binding     FAIL %v\n", networkErr)
			} else if detail, bindingErr := proxmox.ValidatePhysicalBinding(s, interfaces); bindingErr != nil {
				failed = true
				fmt.Fprintf(out, "Physical binding     FAIL %v\n", bindingErr)
			} else {
				fmt.Fprintf(out, "Physical binding     PASS %s\n", detail)
			}
		}
	} else {
		fmt.Fprintln(out, "Platform guests       NOT TESTED (use --live)")
	}
	if failed {
		return fmt.Errorf("doctor found absent or inconsistent projections")
	}
	return nil
}

func runBootstrap(args []string, out interface{ Write([]byte) (int, error) }) error {
	fs := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	recoveryConfirmed := fs.Bool("recovery-confirmed", false, "confirm an independent Age recovery copy exists")
	operatorKey := fs.String("operator-key", "", "operator SSH public key path")
	initialUser := fs.String("initial-user", "root", "initial SSH user on the fresh Proxmox host")
	knownHosts := fs.String("known-hosts", "", "optional SSH known-hosts file for bootstrap")
	proxmoxCA := fs.String("proxmox-ca", "", "Proxmox API CA PEM file")
	insecure := fs.Bool("insecure", false, "explicitly allow self-signed Proxmox API TLS during bootstrap")
	opnsenseISO := fs.String("opnsense-iso", "", "verified OPNsense ISO path on Proxmox storage")
	trunkInterface := fs.String("trunk-interface", "", "explicit physical trunk interface when discovery finds multiple candidates")
	dryRun := fs.Bool("dry-run", false, "render and validate the bootstrap plan without connecting")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	plan, err := proxmox.PlanFromSite(s)
	if err != nil {
		return err
	}
	if s.BootstrapAddress == "" {
		return errors.New("bootstrap endpoint is not configured; use boetticher bootstrap-endpoint set ADDRESS first")
	}
	if !*dryRun {
		if _, err := os.Stat(model.ExpandUserPath(*ageIdentity)); err != nil {
			return fmt.Errorf("Age identity is not available at %s: %w", model.ExpandUserPath(*ageIdentity), err)
		}
		if !*recoveryConfirmed {
			return errors.New("destructive bootstrap requires --recovery-confirmed after an independent Age recovery copy is secured")
		}
	}
	if *operatorKey == "" {
		*operatorKey = defaultOperatorPublicKey()
	}
	if *operatorKey != "" {
		publicKey, err := readOperatorPublicKey(*operatorKey)
		if err != nil && !*dryRun {
			return err
		}
		if err == nil {
			if err := proxmox.ValidatePublicKey(publicKey); err != nil {
				return err
			}
		}
	}
	if *dryRun {
		fmt.Fprintf(out, "Bootstrap plan: PASS model %s\n", plan.ModelRevision)
		fmt.Fprintf(out, "  Proxmox endpoint: %s\n  Firewall VMID: %d\n  OPNsense ISO: %s\n", s.BootstrapAddress, model.ProxmoxVMID, valueOrPlaceholder(*opnsenseISO))
		fmt.Fprintln(out, "  Trust transition: SSH key → labadmin/lab-jump → scoped API token → SOPS")
		fmt.Fprintln(out, "  Destructive actions: NOT RUN (dry-run)")
		return nil
	}
	if *opnsenseISO == "" {
		return errors.New("--opnsense-iso is required for live bootstrap")
	}
	publicKey, err := readOperatorPublicKey(*operatorKey)
	if err != nil {
		return err
	}
	runner := proxmox.SSHRunner{KnownHosts: *knownHosts}
	ctx := context.Background()
	if err := proxmox.InstallOperatorKey(ctx, runner, s.BootstrapAddress, *initialUser, publicKey); err != nil {
		return fmt.Errorf("install operator SSH key: %w", err)
	}
	allowedDestinations := jumpDestinations(s)
	if err := proxmox.ConfigureIdentities(ctx, runner, s.BootstrapAddress, *initialUser, publicKey, allowedDestinations); err != nil {
		return fmt.Errorf("configure Proxmox administrative and bastion identities: %w", err)
	}
	tokenSecret, err := proxmox.CreateScopedCredentialsWithRole(ctx, runner, s.BootstrapAddress, *initialUser, "labadmin@pve", "boetticher", "BoetticherProvisioner")
	if err != nil {
		return fmt.Errorf("create scoped Proxmox API credentials: %w", err)
	}
	credentials := site.ProxmoxCredentials{APIUser: "labadmin@pve", TokenID: "boetticher", TokenSecret: tokenSecret}
	if err := site.StoreProxmoxCredentials(*siteDir, s, credentials); err != nil {
		return fmt.Errorf("store Proxmox credentials in SOPS: %w", err)
	}
	client, err := proxmox.NewClient(proxmox.Config{
		BaseURL: "https://" + s.BootstrapAddress + ":8006/api2/json", User: credentials.APIUser,
		TokenID: credentials.TokenID, TokenSecret: credentials.TokenSecret, CAFile: *proxmoxCA, Insecure: *insecure,
	})
	if err != nil {
		return err
	}
	version, err := client.Version(ctx)
	if err != nil {
		return fmt.Errorf("authenticate to Proxmox with scoped identity: %w", err)
	}
	discovery, err := proxmox.DiscoverPhysicalNetworkWithSelection(ctx, client, plan.Node, s.BootstrapAddress, s.PhysicalNetwork.Trunk.Name, *trunkInterface)
	if err != nil {
		return err
	}
	printPhysicalDiscovery(out, discovery)
	if discovery.Mode == networkmodel.ModeSelectionNeeded {
		return errors.New("HOLD: multiple eligible trunk interfaces require --trunk-interface selection before bootstrap can mutate networking")
	}
	if err := proxmox.EnsureVirtualBridge(ctx, client, plan.Node); err != nil {
		return err
	}
	trunkChanged := false
	if discovery.Trunk != nil && discovery.Trunk.Bridge != "vmbr1" {
		if err := proxmox.AttachTrunk(ctx, client, plan.Node, discovery.Trunk.Name, s.BootstrapAddress); err != nil {
			return err
		}
		trunkChanged = true
	}
	var postInterfaces []proxmox.NetworkInterface
	if err := client.NodeNetwork(ctx, plan.Node, &postInterfaces); err != nil {
		if trunkChanged {
			return rollbackTrunkChange(ctx, client, plan.Node, discovery.Trunk.Name, s.BootstrapAddress, "HOLD: bootstrap network mutation could not be re-read", err)
		}
		return fmt.Errorf("HOLD: bootstrap network state could not be re-read: %w", err)
	}
	configuredTrunk := ""
	if discovery.Trunk != nil {
		configuredTrunk = discovery.Trunk.Name
	}
	postDiscovery, err := proxmox.AnalyzePhysicalNetwork(postInterfaces, s.BootstrapAddress, configuredTrunk)
	if err != nil {
		if trunkChanged {
			return rollbackTrunkChange(ctx, client, plan.Node, discovery.Trunk.Name, s.BootstrapAddress, "HOLD: bootstrap network mutation failed physical validation", err)
		}
		return fmt.Errorf("HOLD: bootstrap network state failed physical validation: %w", err)
	}
	s.PhysicalNetwork.Upstream = model.PhysicalNIC{Name: postDiscovery.Upstream.Name, PermanentMAC: postDiscovery.Upstream.PermanentMAC, PCIAddress: postDiscovery.Upstream.PCIAddress}
	if postDiscovery.Trunk == nil {
		s.PhysicalNetwork.Mode = model.ModeVirtualOnly
		s.PhysicalNetwork.Trunk = model.PhysicalNIC{}
	} else {
		s.PhysicalNetwork.Mode = model.ModePhysicalTrunk
		s.PhysicalNetwork.Trunk = model.PhysicalNIC{Name: postDiscovery.Trunk.Name, PermanentMAC: postDiscovery.Trunk.PermanentMAC, PCIAddress: postDiscovery.Trunk.PCIAddress}
	}
	if _, err := proxmox.ValidatePhysicalBinding(s, postInterfaces); err != nil {
		if trunkChanged {
			return rollbackTrunkChange(ctx, client, plan.Node, discovery.Trunk.Name, s.BootstrapAddress, "HOLD: bootstrap network binding validation failed", err)
		}
		return fmt.Errorf("HOLD: bootstrap network binding validation failed: %w", err)
	}
	if err := site.Save(*siteDir, s); err != nil {
		if trunkChanged {
			return rollbackTrunkChange(ctx, client, plan.Node, discovery.Trunk.Name, s.BootstrapAddress, "HOLD: bootstrap network binding could not be persisted", err)
		}
		return fmt.Errorf("HOLD: bootstrap network binding could not be persisted: %w", err)
	}
	plan, err = proxmox.PlanFromSite(s)
	if err != nil {
		return fmt.Errorf("HOLD: recompute platform plan after physical binding: %w", err)
	}
	if err := writeModelProjections(*siteDir, s); err != nil {
		return fmt.Errorf("HOLD: bootstrap network binding was persisted but projections could not be regenerated: %w", err)
	}
	if err := writePhysicalDiscovery(*siteDir, s, postDiscovery); err != nil {
		return fmt.Errorf("HOLD: bootstrap network binding was persisted but physical evidence could not be written: %w", err)
	}
	if err := rebuildPortal(*siteDir, s); err != nil {
		return fmt.Errorf("HOLD: bootstrap network binding was persisted but portal could not be regenerated: %w", err)
	}
	if err := proxmox.EnsureFirewallVM(ctx, client, plan, *opnsenseISO); err != nil {
		return err
	}
	if err := client.StartVM(ctx, plan.Node, model.ProxmoxVMID); err != nil {
		return fmt.Errorf("start OPNsense VM: %w", err)
	}
	hostKey, err := sshconfig.ScanHostKey(ctx, s.BootstrapAddress)
	if err != nil {
		return fmt.Errorf("record Proxmox SSH host identity: %w", err)
	}
	if err := site.Save(*siteDir, s); err != nil {
		return fmt.Errorf("HOLD: bootstrap completed network mutation but physical binding could not be persisted: %w", err)
	}
	plan, err = proxmox.PlanFromSite(s)
	if err != nil {
		return err
	}
	if err := writeProjection(filepath.Join(*siteDir, "generated", "bootstrap.json"), struct {
		ModelRevision    string `json:"model_revision"`
		ProxmoxVersion   string `json:"proxmox_version"`
		BootstrapAddress string `json:"bootstrap_address"`
		SSHHostKey       string `json:"ssh_host_key"`
		FirewallVMID     int    `json:"firewall_vmid"`
		Status           string `json:"status"`
	}{plan.ModelRevision, version, s.BootstrapAddress, hostKey, model.ProxmoxVMID, "proxmox-trust-transition-complete"}); err != nil {
		return err
	}
	if err := writeModelProjections(*siteDir, s); err != nil {
		return err
	}
	if err := writePhysicalDiscovery(*siteDir, s, postDiscovery); err != nil {
		return err
	}
	if err := rebuildPortal(*siteDir, s); err != nil {
		return err
	}
	fmt.Fprintf(out, "Proxmox bootstrap: PASS authenticated with scoped identity on %s\n", version)
	fmt.Fprintln(out, "Firewall VM: PASS created or already present and started")
	fmt.Fprintln(out, "OPNsense installation/bootstrap: HOLD qualified unattended installer and interface-address path not yet exercised on a fresh VM")
	fmt.Fprintln(out, "Initial root/bootstrap authentication: no longer required for routine boetticher access")
	return errors.New("HOLD: OPNsense greenfield bootstrap is not yet qualified; Proxmox trust transition completed")
}

func runProvision(args []string, out interface{ Write([]byte) (int, error) }) error {
	fs := flag.NewFlagSet("provision", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	proxmoxCA := fs.String("proxmox-ca", "", "Proxmox API CA PEM file")
	insecure := fs.Bool("insecure", false, "explicitly allow self-signed Proxmox API TLS")
	debianTemplate := fs.String("debian-template", "local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst", "Proxmox Debian LXC template")
	dryRun := fs.Bool("dry-run", false, "render and validate the provisioning plan without connecting")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	plan, err := proxmox.PlanFromSite(s)
	if err != nil {
		return err
	}
	if *dryRun {
		fmt.Fprintf(out, "Proxmox provisioning plan: PASS model %s (%d guests)\n", plan.ModelRevision, len(plan.Guests))
		fmt.Fprintf(out, "  Storage target: %s\n  Firewall VM: provisioned by bootstrap\n  Debian template: %s\n", plan.Storage, *debianTemplate)
		return nil
	}
	client, credentials, err := loadProxmoxClient(*siteDir, s, *ageIdentity, *proxmoxCA, *insecure)
	if err != nil {
		return err
	}
	if err := proxmox.Provision(context.Background(), client, plan, *debianTemplate); err != nil {
		return err
	}
	if err := writeModelProjections(*siteDir, s); err != nil {
		return err
	}
	if err := rebuildPortal(*siteDir, s); err != nil {
		return err
	}
	fmt.Fprintf(out, "Proxmox provisioning: PASS model %s via %s\n", plan.ModelRevision, credentials.APIUser)
	return nil
}

func runConverge(args []string, out interface{ Write([]byte) (int, error) }) error {
	fs := flag.NewFlagSet("converge", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	opnsenseURL := fs.String("opnsense-url", "https://10.10.99.1", "OPNsense API base URL")
	opnsenseCA := fs.String("opnsense-ca", "", "OPNsense API CA PEM file")
	insecure := fs.Bool("insecure", false, "explicitly allow self-signed OPNsense API TLS")
	playbook := fs.String("ansible-playbook", "ansible/site.yml", "guest convergence playbook")
	dryRun := fs.Bool("dry-run", false, "render and validate policy without connecting")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	plan, err := opnsense.PlanFromSite(s)
	if err != nil {
		return err
	}
	if *dryRun {
		fmt.Fprintf(out, "OPNsense convergence plan: PASS model %s\n", plan.ModelRevision)
		fmt.Fprintf(out, "  VLANs: %d\n  Kea subnets: %d\n  Firewall rules: %d\n", len(plan.VLANs), len(plan.Zones), len(plan.FirewallRules))
		return nil
	}
	if err := writeModelProjections(*siteDir, s); err != nil {
		return err
	}
	credentials, err := site.LoadOPNsenseCredentials(*siteDir, s, *ageIdentity)
	if err != nil {
		return fmt.Errorf("load encrypted OPNsense API credentials: %w", err)
	}
	ddnsTSIG, err := site.LoadDDNSTSIG(*siteDir, s, *ageIdentity)
	if err != nil {
		return fmt.Errorf("load encrypted DDNS TSIG material: %w", err)
	}
	client, err := opnsense.NewClient(opnsense.Config{BaseURL: *opnsenseURL, User: credentials.APIKey, Secret: credentials.APISecret, CAFile: *opnsenseCA, Insecure: *insecure})
	if err != nil {
		return err
	}
	var firmware map[string]any
	if err := client.FirmwareStatus(context.Background(), &firmware); err != nil {
		return fmt.Errorf("authenticate to OPNsense API: %w", err)
	}
	if err := client.ApplyVLANs(context.Background(), plan); err != nil {
		return err
	}
	if err := client.ApplyDDNS(context.Background(), plan); err != nil {
		return err
	}
	if err := client.ApplyKeaWithTSIG(context.Background(), plan, ddnsTSIG); err != nil {
		return err
	}
	if err := client.ApplyFirewall(context.Background(), plan); err != nil {
		return err
	}
	variables, err := ansible.Variables(s)
	if err != nil {
		return err
	}
	var runtimeVariables map[string]any
	if err := json.Unmarshal(variables, &runtimeVariables); err != nil {
		return fmt.Errorf("decode Ansible variables: %w", err)
	}
	runtimeVariables["portal_source_dir"] = filepath.Join(*siteDir, "generated", "portal")
	runtimeVariables["ddns_tsig_secret"] = ddnsTSIG
	variables, err = json.MarshalIndent(runtimeVariables, "", "  ")
	if err != nil {
		return err
	}
	variables = append(variables, '\n')
	inventoryPath := filepath.Join(*siteDir, "generated", "ansible", "inventory.ini")
	if err := ansible.Run(context.Background(), *playbook, inventoryPath, variables); err != nil {
		return err
	}
	if err := writeModelProjections(*siteDir, s); err != nil {
		return err
	}
	if err := rebuildPortal(*siteDir, s); err != nil {
		return err
	}
	fmt.Fprintf(out, "OPNsense convergence: PASS model %s; API authenticated and policy applied\n", plan.ModelRevision)
	return nil
}

func loadProxmoxClient(siteDir string, s model.Site, ageIdentity, caFile string, insecure bool) (*proxmox.Client, site.ProxmoxCredentials, error) {
	if s.BootstrapAddress == "" {
		return nil, site.ProxmoxCredentials{}, errors.New("bootstrap endpoint is not configured")
	}
	credentials, err := site.LoadProxmoxCredentials(siteDir, s, ageIdentity)
	if err != nil {
		return nil, site.ProxmoxCredentials{}, fmt.Errorf("load encrypted Proxmox API credentials: %w", err)
	}
	client, err := proxmox.NewClient(proxmox.Config{BaseURL: "https://" + s.BootstrapAddress + ":8006/api2/json", User: credentials.APIUser, TokenID: credentials.TokenID, TokenSecret: credentials.TokenSecret, CAFile: caFile, Insecure: insecure})
	if err != nil {
		return nil, site.ProxmoxCredentials{}, err
	}
	return client, credentials, nil
}

func checkBootstrapEndpoint(siteDir string, s model.Site) error {
	data, err := os.ReadFile(filepath.Join(siteDir, "generated", "bootstrap.json"))
	if err != nil {
		return fmt.Errorf("bootstrap evidence is absent; run bootstrap first: %w", err)
	}
	var evidence struct {
		BootstrapAddress string `json:"bootstrap_address"`
		SSHHostKey       string `json:"ssh_host_key"`
	}
	if err := json.Unmarshal(data, &evidence); err != nil {
		return fmt.Errorf("decode bootstrap evidence: %w", err)
	}
	if evidence.BootstrapAddress != s.BootstrapAddress {
		return fmt.Errorf("recorded address %s is stale; use boetticher bootstrap-endpoint set ADDRESS then regenerate SSH configuration", evidence.BootstrapAddress)
	}
	connection, err := net.DialTimeout("tcp", net.JoinHostPort(s.BootstrapAddress, "22"), 5*time.Second)
	if err != nil {
		return fmt.Errorf("bootstrap address %s is not reachable on SSH: %w", s.BootstrapAddress, err)
	}
	_ = connection.Close()
	hostKey, err := sshconfig.ScanHostKey(context.Background(), s.BootstrapAddress)
	if err != nil {
		return err
	}
	if hostKey != evidence.SSHHostKey {
		return errors.New("returned SSH host key does not match recorded Proxmox identity; address may be stale or host replaced")
	}
	return nil
}

func runSSHJourney(configPath string) error {
	command := exec.Command("ssh", "-F", model.ExpandUserPath(configPath), "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no", "dns01", "true")
	if err := command.Run(); err != nil {
		return fmt.Errorf("authenticated SSH journey failed: %w", err)
	}
	return nil
}

func jumpDestinations(s model.Site) []string {
	result := []string{}
	for _, m := range s.Modules {
		if m.ProductOwned && m.SSHManaged && m.JumpAllowed {
			port := m.SSHPort
			if port == 0 {
				port = 22
			}
			result = append(result, fmt.Sprintf("%s:%d", m.Address, port))
		}
	}
	sort.Strings(result)
	return result
}

func defaultOperatorPublicKey() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	for _, name := range []string{"id_ed25519.pub", "id_ecdsa.pub", "id_rsa.pub"} {
		path := filepath.Join(home, ".ssh", name)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

func readOperatorPublicKey(path string) (string, error) {
	if path == "" {
		return "", errors.New("operator SSH public key is required; use --operator-key PATH")
	}
	data, err := os.ReadFile(model.ExpandUserPath(path))
	if err != nil {
		return "", fmt.Errorf("read operator SSH public key: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

func valueOrPlaceholder(value string) string {
	if value == "" {
		return "<required for live run>"
	}
	return value
}

func runIntegrationGate(command string, args []string, out interface{ Write([]byte) (int, error) }) error {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	recoveryConfirmed := fs.Bool("recovery-confirmed", false, "confirm an independent Age recovery copy exists")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	if command == "bootstrap" {
		identityPath := model.ExpandUserPath(*ageIdentity)
		if _, err := os.Stat(identityPath); err != nil {
			return fmt.Errorf("HOLD: Age identity is not available at %s", identityPath)
		}
		if !*recoveryConfirmed {
			return fmt.Errorf("HOLD: destructive bootstrap requires --recovery-confirmed after an independent Age recovery copy is secured")
		}
	}
	if command == "upgrade" {
		fmt.Fprintln(out, "HOLD: compatibility qualification and migration are required before upgrade")
	} else {
		fmt.Fprintf(out, "HOLD: %s requires the authenticated Proxmox/OPNsense integration path; no mutation was performed\n", command)
	}
	_ = s
	return fmt.Errorf("%s integration gate is not yet satisfied", command)
}

func writeModelProjection(dir string, s model.Site) error {
	revision, err := s.Revision()
	if err != nil {
		return err
	}
	modelForProjection := s.Normalize()
	modelForProjection.SSHIdentityFile = ""
	document := struct {
		ModelRevision string     `json:"model_revision"`
		Model         model.Site `json:"model"`
	}{ModelRevision: revision, Model: modelForProjection}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	return writePublic(filepath.Join(dir, "generated", "model.json"), append(data, '\n'))
}

func writeModelProjections(dir string, s model.Site) error {
	if err := writeModelProjection(dir, s); err != nil {
		return err
	}
	revision, err := s.Revision()
	if err != nil {
		return err
	}
	normalized := s.Normalize()
	proxmoxPlan, err := proxmox.PlanFromSite(s)
	if err != nil {
		return err
	}
	opnsensePlan, err := opnsense.PlanFromSite(s)
	if err != nil {
		return err
	}
	opnsenseBootstrap, err := opnsense.BootstrapPlanFromSite(s)
	if err != nil {
		return err
	}
	if err := writeProjection(filepath.Join(dir, "generated", "inventory.json"), struct {
		ModelRevision string         `json:"model_revision"`
		Modules       []model.Module `json:"modules"`
	}{revision, normalized.Modules}); err != nil {
		return err
	}
	if err := writeProjection(filepath.Join(dir, "generated", "opnsense", "desired-policy.json"), opnsensePlan); err != nil {
		return err
	}
	if err := writeProjection(filepath.Join(dir, "generated", "opnsense", "bootstrap.json"), opnsenseBootstrap); err != nil {
		return err
	}
	dnsPlan, err := dns.PlanFromSite(s)
	if err != nil {
		return err
	}
	if err := writeProjection(filepath.Join(dir, "generated", "dns", "desired-state.json"), dnsPlan); err != nil {
		return err
	}
	backupPlan, err := backup.PlanFromSite(s)
	if err != nil {
		return err
	}
	if err := writeProjection(filepath.Join(dir, "generated", "backup", "desired-policy.json"), backupPlan); err != nil {
		return err
	}
	if err := writeProjection(filepath.Join(dir, "generated", "proxmox", "desired-state.json"), proxmoxPlan); err != nil {
		return err
	}
	zabbixPlan, err := zabbix.PlanFromSite(s)
	if err != nil {
		return err
	}
	if err := writeProjection(filepath.Join(dir, "generated", "zabbix", "provisioning.json"), zabbixPlan); err != nil {
		return err
	}
	if err := writeCurrentStatus(dir, revision); err != nil {
		return err
	}
	inventory, err := ansible.Inventory(s)
	if err != nil {
		return err
	}
	if err := writePublic(filepath.Join(dir, "generated", "ansible", "inventory.ini"), []byte(inventory)); err != nil {
		return err
	}
	variables, err := ansible.Variables(s)
	if err != nil {
		return err
	}
	if err := writePublic(filepath.Join(dir, "generated", "ansible", "variables.json"), variables); err != nil {
		return err
	}
	sshContent := "# Managed by boetticher. Do not edit.\n# boetticher-model-revision: " + revision + "\n# Bootstrap endpoint is not configured; run boetticher bootstrap-endpoint set ADDRESS.\n"
	if s.BootstrapAddress != "" {
		sshContent, err = sshconfig.Render(s, time.Now().UTC())
		if err != nil {
			return err
		}
	}
	if err := writePublic(filepath.Join(dir, "generated", "ssh", "boetticher.conf"), []byte(sshContent)); err != nil {
		return err
	}
	if err := writeAccessProjection(dir, s); err != nil {
		return err
	}
	return writePhysicalDiscovery(dir, s, loadPhysicalDiscovery(dir, s))
}

func physicalDiscoveryFromSite(s model.Site) networkmodel.Discovery {
	upstream := networkmodel.Interface{Name: s.PhysicalNetwork.Upstream.Name, PermanentMAC: s.PhysicalNetwork.Upstream.PermanentMAC, PCIAddress: s.PhysicalNetwork.Upstream.PCIAddress, PhysicalEthernet: s.PhysicalNetwork.Upstream.Name != ""}
	var trunk *networkmodel.Interface
	if s.PhysicalNetwork.Trunk.Name != "" {
		value := networkmodel.Interface{Name: s.PhysicalNetwork.Trunk.Name, PermanentMAC: s.PhysicalNetwork.Trunk.PermanentMAC, PCIAddress: s.PhysicalNetwork.Trunk.PCIAddress, PhysicalEthernet: true}
		trunk = &value
	}
	return networkmodel.Discovery{Mode: s.PhysicalNetwork.Mode, BootstrapAddress: s.BootstrapAddress, Upstream: upstream, Trunk: trunk, Status: "MODEL", Explanation: "persisted installation binding; live hardware evidence requires preflight or doctor --live"}
}

func writePhysicalDiscovery(dir string, s model.Site, discovery networkmodel.Discovery) error {
	revision, err := s.Revision()
	if err != nil {
		return err
	}
	return writeProjection(filepath.Join(dir, "generated", "network", "physical.json"), struct {
		ModelRevision string                 `json:"model_revision"`
		GeneratedAt   string                 `json:"generated_at"`
		Discovery     networkmodel.Discovery `json:"discovery"`
	}{revision, time.Now().UTC().Format(time.RFC3339), discovery})
}

func writeAccessProjection(dir string, s model.Site) error {
	policy, err := sshconfig.RenderBastionPolicy(s)
	if err != nil {
		return err
	}
	return writePublic(filepath.Join(dir, "generated", "ssh", "lab-jump.conf"), []byte(policy))
}

func rebuildPortal(dir string, s model.Site) error {
	revision, err := s.Revision()
	if err != nil {
		return err
	}
	return portal.Build(s, filepath.Join(dir, "generated", "portal"), "docs", loadEvidence(dir, revision), loadPhysicalDiscovery(dir, s), time.Now().UTC())
}

func loadPhysicalDiscovery(dir string, s model.Site) networkmodel.Discovery {
	data, err := os.ReadFile(filepath.Join(dir, "generated", "network", "physical.json"))
	if err == nil {
		var document struct {
			ModelRevision string                 `json:"model_revision"`
			Discovery     networkmodel.Discovery `json:"discovery"`
		}
		if json.Unmarshal(data, &document) == nil {
			if revision, revisionErr := s.Revision(); revisionErr == nil && document.ModelRevision == revision {
				return document.Discovery
			}
		}
	}
	return physicalDiscoveryFromSite(s)
}

func writeProjection(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writePublic(path, append(data, '\n'))
}

func checkRevisionFile(path, revision string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !strings.Contains(string(data), revision) {
		return fmt.Errorf("model revision is not current")
	}
	return nil
}

func loadEvidence(dir, expectedRevision string) portal.Evidence {
	data, err := os.ReadFile(filepath.Join(dir, "generated", "verification.json"))
	if err != nil {
		return portal.Evidence{}
	}
	var document struct {
		ModelRevision string          `json:"model_revision"`
		Evidence      portal.Evidence `json:"evidence"`
	}
	if json.Unmarshal(data, &document) == nil && document.ModelRevision == expectedRevision {
		return document.Evidence
	}
	return portal.Evidence{}
}

func writeCurrentStatus(dir, revision string) error {
	status := "NOT TESTED"
	data, err := os.ReadFile(filepath.Join(dir, "generated", "status.json"))
	if err == nil {
		var current struct {
			ModelRevision string `json:"model_revision"`
			Status        string `json:"status"`
		}
		if json.Unmarshal(data, &current) == nil && current.ModelRevision == revision && current.Status != "" {
			status = current.Status
		} else if current.Status != "" {
			status = "STALE"
		}
	}
	return writeProjection(filepath.Join(dir, "generated", "status.json"), struct {
		ModelRevision string `json:"model_revision"`
		Status        string `json:"status"`
		GeneratedAt   string `json:"generated_at"`
	}{revision, status, time.Now().UTC().Format(time.RFC3339)})
}

func sortedSSHModules(s model.Site) []model.Module {
	modules := []model.Module{}
	for _, m := range s.Modules {
		if m.SSHManaged {
			modules = append(modules, m)
		}
	}
	sort.Slice(modules, func(i, j int) bool { return modules[i].Name < modules[j].Name })
	return modules
}

func toolVersion(tool string) string {
	args := []string{"--version"}
	if tool == "ssh" {
		args = []string{"-V"}
	}
	command := exec.Command(tool, args...)
	data, err := command.CombinedOutput()
	if err != nil {
		if len(data) == 0 {
			return "version unavailable"
		}
	}
	line := strings.TrimSpace(strings.Split(string(data), "\n")[0])
	return line
}

func validateToolVersion(tool, version string) error {
	if version == "" || version == "version unavailable" {
		return fmt.Errorf("version unavailable")
	}
	switch tool {
	case "ssh":
		if !strings.Contains(version, "OpenSSH") {
			return fmt.Errorf("unrecognized OpenSSH version")
		}
	case "age-keygen":
		if !strings.HasPrefix(version, "v") {
			return fmt.Errorf("unrecognized Age version")
		}
	case "sops":
		if !strings.HasPrefix(version, "sops ") {
			return fmt.Errorf("unrecognized SOPS version")
		}
	case "tofu":
		if !strings.HasPrefix(version, "OpenTofu v") {
			return fmt.Errorf("OpenTofu is required")
		}
	case "ansible":
		if !strings.HasPrefix(version, "ansible [core ") {
			return fmt.Errorf("Ansible Core is required")
		}
	}
	return nil
}

func installSSHInclude() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	path := filepath.Join(home, ".ssh", "config")
	include := "Include ~/.ssh/config.d/*"
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		data = nil
	} else if err != nil {
		return err
	}
	if strings.Contains(string(data), include) {
		return nil
	}
	data = append(data, []byte("\n"+include+"\n")...)
	return sshconfig.Write(path, data, true)
}

func writePrivate(path string, data []byte) error {
	return writeFile(path, data, 0600)
}

func writePublic(path string, data []byte) error {
	return writeFile(path, data, 0644)
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".boetticher-output-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
