package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gofastercloud/boetticher/internal/ansible"
	"github.com/gofastercloud/boetticher/internal/artifacts"
	"github.com/gofastercloud/boetticher/internal/companion"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
	"github.com/gofastercloud/boetticher/internal/pathguard"
	"github.com/gofastercloud/boetticher/internal/pki"
	"github.com/gofastercloud/boetticher/internal/proxmox"
	"github.com/gofastercloud/boetticher/internal/secrets"
	"github.com/gofastercloud/boetticher/internal/site"
	"github.com/gofastercloud/boetticher/internal/sshconfig"
	"github.com/gofastercloud/boetticher/internal/streamdeck"
)

const kioskClientName = "lab-display-01-kiosk"
const companionStreamDeckIdentity = "companion-streamdeck"

var companionReadCredential = secrets.CredentialSpec{Name: "pulse-token", Unit: "boetticher-companion.service", StorePath: "/var/lib/boetticher/credentials/companion-read.cred", RuntimeRef: "/run/credentials/boetticher-companion.service/pulse-token"}
var companionAgentCredential = secrets.CredentialSpec{Name: "pulse-agent-token", Unit: "pulse-agent.service", StorePath: "/var/lib/boetticher/credentials/companion-agent.cred", RuntimeRef: "/run/credentials/pulse-agent.service/pulse-agent-token"}

func runCompanion(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher companion add|setup|status|migrate [options]")
	}
	switch args[0] {
	case "add":
		return runCompanionAdd(args[1:], out)
	case "setup":
		return runCompanionSetup(args[1:], out)
	case "status":
		return runCompanionStatus(args[1:], out)
	case "migrate":
		return runCompanionMigrate(args[1:], out)
	default:
		return fmt.Errorf("unknown companion command %q", args[0])
	}
}

func runCompanionAdd(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("companion add", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	mac := fs.String("mac", "", "physical Ethernet MAC of the Companion eth0 interface")
	displayEnabled := fs.Bool("display", true, "enable the HDMI dashboard")
	deckEnabled := fs.Bool("streamdeck", true, "enable the supported StreamDeck")
	agentEnabled := fs.Bool("pulse-agent", true, "enable local Pulse reporting")
	blinktEnabled := fs.Bool("blinkt", false, "enable the eight-LED Blinkt status display")
	deckSerial := fs.String("streamdeck-serial", "", "select one supported StreamDeck by serial")
	confirm := fs.Bool("confirm", false, "save the Companion desired state")
	dryRun := fs.Bool("dry-run", false, "show the derived reservation without changing desired state")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("companion add does not accept positional arguments")
	}
	if *dryRun && *confirm {
		return errors.New("--dry-run and --confirm cannot be used together")
	}
	canonicalMAC, err := canonicalMACAddress(*mac)
	if err != nil {
		return fmt.Errorf("companion add requires --mac for the physical eth0 interface: %w", err)
	}
	config, err := site.LoadConfig(*siteDir)
	if err != nil {
		return err
	}
	companion := &model.CompanionConfig{}
	if config.Companion != nil {
		*companion = *config.Companion
	}
	enabled := true
	companion.Enabled = &enabled
	companion.EthernetMAC = canonicalMAC
	if companion.Display == nil {
		companion.Display = &model.CompanionCapabilityConfig{Enabled: &enabled}
	}
	if companion.StreamDeck == nil {
		companion.StreamDeck = &model.CompanionCapabilityConfig{Enabled: &enabled}
	}
	if companion.PulseAgent == nil {
		companion.PulseAgent = &model.CompanionCapabilityConfig{Enabled: &enabled}
	}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "display":
			companion.Display = &model.CompanionCapabilityConfig{Enabled: displayEnabled}
		case "streamdeck":
			companion.StreamDeck = &model.CompanionCapabilityConfig{Enabled: deckEnabled}
		case "pulse-agent":
			companion.PulseAgent = &model.CompanionCapabilityConfig{Enabled: agentEnabled}
		case "blinkt":
			companion.Blinkt = &model.CompanionCapabilityConfig{Enabled: blinktEnabled}
		case "streamdeck-serial":
			companion.StreamDeckSerial = *deckSerial
		}
	})
	if strings.ContainsAny(companion.StreamDeckSerial, "\"'\\\n\r\t") {
		return errors.New("StreamDeck serial contains unsafe characters")
	}
	config.Companion = companion

	reservation, ok := model.CompanionReservation(companion)
	if !ok {
		return errors.New("companion identity did not produce the fixed SERVERS reservation")
	}
	reservations := make([]model.DHCPReservation, 0, len(config.DHCPReservations))
	for _, existing := range config.DHCPReservations {
		existingMAC, parseErr := canonicalMACAddress(existing.MAC)
		exact := parseErr == nil && existing.Zone == reservation.Zone && strings.EqualFold(existing.Hostname, reservation.Hostname) && existing.Address == reservation.Address && existingMAC == reservation.MAC && existing.VMID == 0
		if exact {
			// Adopt an exact generic reservation into the typed Companion
			// authority instead of persisting two competing representations.
			continue
		}
		if strings.EqualFold(existing.Hostname, reservation.Hostname) || existing.Address == reservation.Address || parseErr == nil && existingMAC == reservation.MAC {
			return fmt.Errorf("existing DHCP reservation %s conflicts with the fixed Companion identity; remove or reconcile it first", existing.Hostname)
		}
		reservations = append(reservations, existing)
	}
	config.DHCPReservations = reservations
	if err := validateComposedConfig(config); err != nil {
		return fmt.Errorf("validate Companion desired state: %w", err)
	}

	fmt.Fprintln(out, "Companion plan")
	fmt.Fprintf(out, "  Hostname  %s\n", reservation.Hostname)
	fmt.Fprintf(out, "  Zone      %s\n", reservation.Zone)
	fmt.Fprintf(out, "  Address   %s\n", reservation.Address)
	fmt.Fprintf(out, "  MAC       %s\n", reservation.MAC)
	fmt.Fprintln(out, "  Mutation  desired state only; no DHCP, SSH, or Pi change")
	if *dryRun {
		fmt.Fprintln(out, "Companion add: PASS dry-run only; desired state was not changed")
		return nil
	}
	if !*confirm {
		return errors.New("companion add changes desired state only; review the fixed reservation and rerun with --confirm")
	}
	if err := site.SaveConfig(*siteDir, config); err != nil {
		return fmt.Errorf("save Companion desired state: %w", err)
	}
	fmt.Fprintln(out, "Companion add: PASS desired state saved; no deployment performed")
	if config.Gateway.Mode == model.GatewayModeManaged {
		if config.PhysicalNetwork.Mode != model.ModePhysicalTrunk {
			fmt.Fprintln(out, "Next action: attach the guarded physical trunk, then run deploy to apply the reservation and bastion route before companion setup")
		} else {
			fmt.Fprintln(out, "Next action: run deploy to apply the reservation and bastion route, then run companion setup")
		}
	} else {
		fmt.Fprintln(out, "Next action: apply the generated external-firewall reservation contract and bastion route, then run companion setup")
	}
	return nil
}

func runCompanionMigrate(args []string, out io.Writer) error {
	args, err := normalizeCompanionMigrationArgs(args)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("companion migrate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	proxmoxCA := fs.String("proxmox-ca", "", "Proxmox API CA PEM file")
	insecure := fs.Bool("insecure", false, "allow explicitly untrusted Proxmox API TLS")
	confirm := fs.Bool("confirm", false, "authorize exact legacy guest and USB mapping removal")
	dryRun := fs.Bool("dry-run", false, "show the migration without changing the site or Proxmox")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("one legacy Proxmox address is required")
	}
	address := fs.Arg(0)
	if err := sshconfig.ValidateBootstrapAddress(address); err != nil {
		return err
	}
	if *dryRun && *confirm {
		return errors.New("--dry-run and --confirm cannot be used together")
	}
	legacyData, err := pathguard.ReadFile(filepath.Join(*siteDir, "site.yml"))
	if err != nil {
		return fmt.Errorf("read site.yml for legacy companion migration: %w", err)
	}
	config, removedBindings, _, err := model.MigrateLegacyStreamDeckConfig(legacyData)
	if err != nil {
		return err
	}
	retained, err := site.LoadRetainedModules(*siteDir)
	if err != nil {
		return fmt.Errorf("read retained module state: %w", err)
	}
	filteredRetained := make([]model.RetainedModule, 0, len(retained))
	removedRetained := 0
	for _, item := range retained {
		if item.Module == "streamdeck" {
			removedRetained++
			continue
		}
		filteredRetained = append(filteredRetained, item)
	}
	migrated, err := site.ComposeConfig(*siteDir, config)
	if err != nil {
		return fmt.Errorf("compose migrated companion state: %w", err)
	}
	migrated.RetainedModules = filteredRetained
	if err := migrated.Validate(); err != nil {
		return fmt.Errorf("validate migrated companion state: %w", err)
	}
	if config.BootstrapAddress != address {
		return fmt.Errorf("legacy Proxmox address %s does not match site bootstrap_address %s", address, config.BootstrapAddress)
	}
	fmt.Fprintf(out, "Legacy StreamDeck: %s VMID %d at %s\n", proxmox.LegacyStreamDeckName, model.LegacyStreamDeckVMID, address)
	fmt.Fprintf(out, "Local cleanup: %d USB binding(s), %d retained module record(s)\n", removedBindings, removedRetained)
	fmt.Fprintln(out, "Result: StreamDeck is staged as a disabled Companion capability; add the physical eth0 MAC separately")
	if *dryRun {
		fmt.Fprintln(out, "Companion migration: PASS dry-run only; no site, SSH, or Proxmox changes made")
		return nil
	}
	if !*confirm {
		return errors.New("HOLD: review the exact legacy identity and rerun with --confirm")
	}

	client, _, err := loadProxmoxClient(*siteDir, migrated, *ageIdentity, *proxmoxCA, *insecure)
	if err != nil {
		return fmt.Errorf("load authenticated Proxmox client for companion migration: %w", err)
	}
	nodes, err := client.Nodes(context.Background())
	if err != nil {
		return fmt.Errorf("discover Proxmox node for companion migration: %w", err)
	}
	node, err := proxmox.ResolveSingleNode(nodes)
	if err != nil {
		return err
	}
	present, err := proxmox.InspectLegacyStreamDeck(context.Background(), client, node)
	if err != nil {
		return err
	}
	if present {
		rootRunner := proxmoxRootSSHRunner(migrated, *siteDir)
		if _, err := rootRunner.RunArgs(context.Background(), migrated.BootstrapAddress, "root", proxmox.LegacyStreamDeckUSBRemovalArgs()); err != nil {
			return fmt.Errorf("remove exact legacy StreamDeck USB mapping before guest removal: %w; legacy site state remains available for retry", err)
		}
		if err := proxmox.RemoveLegacyStreamDeck(context.Background(), client, node); err != nil {
			return fmt.Errorf("remove legacy StreamDeck guest: %w; legacy site state remains available for retry", err)
		}
	}
	if err := site.ApplyLegacyStreamDeckMigration(*siteDir, config, filteredRetained); err != nil {
		return fmt.Errorf("commit companion migration state after legacy guest removal: %w; the old guest was removed and must not be recreated", err)
	}
	if err := writeModelProjections(*siteDir, migrated); err != nil {
		return fmt.Errorf("refresh migrated projections: %w; migrated site state is committed after legacy guest removal", err)
	}
	if present {
		fmt.Fprintln(out, "Legacy guest: PASS exact owned StreamDeck LXC removed and verified absent")
	} else {
		fmt.Fprintln(out, "Legacy guest: PASS exact StreamDeck LXC was already absent")
	}
	fmt.Fprintf(out, "Companion migration: PASS %s migrated; unrelated USB mappings were not selected\n", address)
	fmt.Fprintln(out, "Next action: run companion add --mac MAC --confirm for this site")
	return nil
}

func runCompanionSetup(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("companion setup", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	user := fs.String("user", "pi", "initial SSH user on the Raspberry Pi")
	identity := fs.String("identity-file", "", "private SSH identity file")
	knownHosts := fs.String("known-hosts", "", "strict SSH known-hosts file")
	hostKey := fs.String("host-key", "", "independently verified OpenSSH host public key to enroll")
	port := fs.Int("port", 22, "Raspberry Pi SSH port")
	confirm := fs.Bool("confirm", false, "authorize remote Pi mutation")
	dryRun := fs.Bool("dry-run", false, "render and validate the setup without changing the site or Pi")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("companion setup uses the configured SERVERS reservation and does not accept an address")
	}
	if *port < 1 || *port > 65535 {
		return fmt.Errorf("SSH port %d is outside 1-65535", *port)
	}
	if *user == "root" {
		// Root is supported for already-prepared images, but the normal path is
		// a non-root Raspberry Pi account with passwordless sudo.
		fmt.Fprintln(out, "SSH account: root (CAGE setup will skip privilege escalation)")
	}

	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	reservation, ok := model.CompanionReservation(s.Companion)
	if !ok {
		return errors.New("companion is not configured; run boetticher companion add --mac MAC first")
	}
	address := reservation.Address
	capabilities := s.Companion.Capabilities()
	if *identity == "" {
		*identity = s.SSHIdentityFile
	}
	if *identity == "" {
		*identity = filepath.Join(model.ExpandUserPath("~"), ".ssh", "id_ed25519")
	}
	*identity = model.ExpandUserPath(*identity)
	if *knownHosts == "" {
		*knownHosts = filepath.Join(*siteDir, "generated", "ssh", "companion_known_hosts")
	}
	*knownHosts = model.ExpandUserPath(*knownHosts)
	if err := validateKioskSSHInputs(*identity, *knownHosts, *dryRun); err != nil {
		return err
	}
	platformKnownHosts := deploymentKnownHosts(*siteDir)
	if err := validateKioskSSHInputs(*identity, platformKnownHosts, *dryRun); err != nil {
		return err
	}
	sshContent, err := sshconfig.RenderCompanion(s, *user, *identity, platformKnownHosts, *knownHosts, *port)
	if err != nil {
		return err
	}
	sourceRoot, cleanupSource, err := kioskSourceRoot()
	if err != nil {
		return err
	}
	defer cleanupSource()
	pulseURL := "https://monitor." + s.Network.Domain
	streamDeckBinary := ""
	fmt.Fprintf(out, "Companion target: %s@%s:%d\n", *user, address, *port)
	fmt.Fprintf(out, "Pulse URL: %s\n", pulseURL)
	fmt.Fprintf(out, "Companion source: %s\n", filepath.Join(sourceRoot, "pi", "kiosk"))
	fmt.Fprintf(out, "Capabilities: display=%t streamdeck=%t pulse-agent=%t blinkt=%t\n", capabilities.Display, capabilities.StreamDeck, capabilities.PulseAgent, capabilities.Blinkt)
	fmt.Fprintf(out, "Host-key trust: %s\n", *knownHosts)
	if *dryRun {
		fmt.Fprintln(out, "Companion setup: PASS dry-run only; no PKI, site, SSH, or remote changes made")
		return nil
	}
	if !*confirm {
		return errors.New("companion setup changes the remote Pi and local PKI runtime; rerun with --confirm")
	}
	statusBinary, err := artifacts.ResolveImportedCompanionStatus(*siteDir)
	if err != nil {
		return err
	}
	if capabilities.StreamDeck {
		streamDeckBinary, err = companionStreamDeckBinary(*siteDir, false)
		if err != nil {
			return err
		}
	}
	if err := validateKioskSSHInputs(*identity, *knownHosts, false); err != nil {
		return err
	}
	if _, err := sshconfig.ReadHostKey(*knownHosts, model.CompanionHostname); err != nil {
		if *hostKey == "" {
			return fmt.Errorf("refusing unknown Raspberry Pi host key: %w; enroll an independently verified key with --host-key", err)
		}
		if err := os.MkdirAll(filepath.Dir(*knownHosts), 0700); err != nil {
			return fmt.Errorf("create SSH known-hosts directory: %w", err)
		}
		if err := sshconfig.AddKnownHostKey(*knownHosts, model.CompanionHostname, *hostKey); err != nil {
			return err
		}
	} else if *hostKey != "" {
		if err := sshconfig.AddKnownHostKey(*knownHosts, model.CompanionHostname, *hostKey); err != nil {
			return err
		}
	}

	var pulseAgentToken string
	if capabilities.PulseAgent {
		pulseAgentToken, err = site.LoadPlatformSecret(*siteDir, s, *ageIdentity, "companion_agent_token")
		if err != nil {
			return fmt.Errorf("load encrypted Pulse agent token (run boetticher deploy first): %w", err)
		}
	}
	pulseReadToken, err := site.LoadPlatformSecret(*siteDir, s, *ageIdentity, "companion_read_token")
	if err != nil {
		return fmt.Errorf("load Companion read token (run boetticher deploy first): %w", err)
	}
	authority, err := site.LoadAuthority(*siteDir, s, *ageIdentity)
	if err != nil {
		return fmt.Errorf("load Boetticher PKI authority: %w", err)
	}
	consoleConfig := companion.Config{PulseURL: pulseURL, CAFile: "/etc/boetticher/companion-ca.pem", EthernetMAC: s.Companion.EthernetMAC, Address: reservation.Address, Gateway: "10.10.20.1", DNS: "10.10.10.10", DNSName: "monitor." + s.Network.Domain, DNSAddress: "10.10.10.20", AgentID: "boetticher-companion-" + strings.ReplaceAll(s.Companion.EthernetMAC, ":", ""), AgentHostname: model.CompanionHostname, Display: capabilities.Display, StreamDeck: capabilities.StreamDeck, PulseAgent: capabilities.PulseAgent, Blinkt: capabilities.Blinkt}
	consoleConfig.AirVPN = modules.IsEnabled(s, "airvpn")
	consoleConfig.Tailnet = modules.IsEnabled(s, "tailnet-router")
	variables, err := json.MarshalIndent(map[string]any{
		"kiosk_become":                     *user != "root",
		"kiosk_display_enabled":            capabilities.Display,
		"kiosk_streamdeck_enabled":         capabilities.StreamDeck,
		"kiosk_pulse_agent_enabled":        capabilities.PulseAgent,
		"kiosk_blinkt_enabled":             capabilities.Blinkt,
		"companion_config":                 consoleConfig,
		"companion_binary":                 statusBinary,
		"companion_operator_user":          *user,
		"kiosk_source_dir":                 filepath.Join(sourceRoot, "pi", "kiosk"),
		"kiosk_pulse_url":                  pulseURL,
		"kiosk_pulse_agent_hostname":       model.CompanionHostname,
		"kiosk_pulse_agent_id":             consoleConfig.AgentID,
		"kiosk_pulse_agent_version":        model.PulseAgentVersion,
		"kiosk_pulse_agent_release_url":    model.PulseAgentARM64ReleaseURL,
		"kiosk_pulse_agent_release_sha256": model.PulseAgentARM64ReleaseSHA256,
		"streamdeck_binary":                streamDeckBinary,
		"streamdeck_vendor_id":             streamdeck.DefaultVendorID,
		"streamdeck_product_id":            streamdeck.DefaultProductID,
		"streamdeck_model":                 streamdeck.DefaultModel,
		"streamdeck_serial":                s.Companion.StreamDeckSerial,
		"kiosk_root_ca_pem":                authority.RootCertPEM,
		"kiosk_issuing_ca_pem":             authority.IssuingCertPEM,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode companion Ansible variables: %w", err)
	}
	variables = append(variables, '\n')

	workspace, err := os.MkdirTemp("", ".boetticher-kiosk-*")
	if err != nil {
		return fmt.Errorf("create temporary companion Ansible workspace: %w", err)
	}
	defer os.RemoveAll(workspace)
	inventoryPath := filepath.Join(workspace, "inventory.ini")
	sshConfigPath := filepath.Join(workspace, "ssh.conf")
	playbook := filepath.Join(sourceRoot, "ansible", "companion.yml")
	inventory := "# Temporary Boetticher companion inventory.\n[kiosk]\nboetticher-companion\n\n[kiosk:vars]\nansible_python_interpreter=/usr/bin/python3\n"
	if err := os.WriteFile(inventoryPath, []byte(inventory), 0600); err != nil {
		return fmt.Errorf("write temporary companion inventory: %w", err)
	}
	if err := os.WriteFile(sshConfigPath, []byte(sshContent), 0600); err != nil {
		return fmt.Errorf("write temporary companion SSH configuration: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := installCompanionCredentials(ctx, companionStatusSSHRunner(sshConfigPath), address, *user, pulseReadToken, pulseAgentToken, capabilities.PulseAgent); err != nil {
		return err
	}
	if _, err := ansible.RunExternal(ctx, playbook, inventoryPath, variables, sshConfigPath, *user); err != nil {
		return fmt.Errorf("configure Raspberry Pi companion: %w", err)
	}
	for _, name := range []string{kioskClientName, companionStreamDeckIdentity} {
		if err := revokeAndRemoveCompanionCertificate(*siteDir, s, name, out); err != nil {
			return fmt.Errorf("retire superseded Companion certificate: %w", err)
		}
	}
	fmt.Fprintf(out, "Companion setup: PASS %s configured; capabilities display=%t streamdeck=%t pulse-agent=%t\n", address, capabilities.Display, capabilities.StreamDeck, capabilities.PulseAgent)
	return nil
}

// installCompanionCredentials is deliberately separate from Ansible variables:
// each token goes only through the host-key-pinned SSH stdin stream and is
// encrypted by systemd-creds on the Pi before the playbook starts.
func installCompanionCredentials(ctx context.Context, runner proxmox.SSHRunner, address, user, readToken, agentToken string, agentEnabled bool) error {
	if _, err := runner.Run(ctx, address, user, companionPrivilegedCommand(user, "install -d -m 0700 -o root -g root /var/lib/boetticher/credentials")); err != nil {
		return fmt.Errorf("prepare Companion encrypted credential store: %w", err)
	}
	privileged := companionCredentialRunner{runner: runner, privileged: user != "root"}
	if err := secrets.InstallCredential(ctx, privileged, address, user, companionReadCredential, []byte(readToken)); err != nil {
		return fmt.Errorf("install Companion read credential: %w", err)
	}
	if agentEnabled {
		if err := secrets.InstallCredential(ctx, privileged, address, user, companionAgentCredential, []byte(agentToken)); err != nil {
			return fmt.Errorf("install Companion report credential: %w", err)
		}
	}
	return nil
}

type companionCredentialRunner struct {
	runner     proxmox.SSHRunner
	privileged bool
}

func (r companionCredentialRunner) RunWithStdin(ctx context.Context, address, user, command string, stdin io.Reader) ([]byte, error) {
	if r.privileged {
		command = "sudo -n " + command
	}
	return r.runner.RunWithStdin(ctx, address, user, command, stdin)
}

func companionPrivilegedCommand(user, command string) string {
	if user == "root" {
		return command
	}
	return "sudo -n " + command
}

func revokeAndRemoveCompanionCertificate(siteDir string, s model.Site, name string, out io.Writer) error {
	runtimeDir := filepath.Join(site.RuntimeDir(s), "pki", name)
	metadataPath := filepath.Join(siteDir, "generated", "pki", name+".yaml")
	certificatePath := filepath.Join(runtimeDir, "client.crt.pem")
	metadataExists := false
	if _, err := os.Lstat(metadataPath); err == nil {
		metadataExists = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if !metadataExists {
		if _, err := os.Lstat(certificatePath); errors.Is(err, os.ErrNotExist) {
			return nil
		} else if err != nil {
			return err
		}
	}
	if err := revokeClient(siteDir, runtimeDir, name, out); err != nil {
		return err
	}
	if err := pathguard.RemoveAll(runtimeDir); err != nil {
		return fmt.Errorf("remove cached certificate: %w", err)
	}
	if err := pathguard.RemoveAll(metadataPath); err != nil {
		return fmt.Errorf("remove cached certificate metadata: %w", err)
	}
	return nil
}

func runCompanionStatus(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("companion status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	user := fs.String("user", "pi", "SSH user on the Raspberry Pi")
	identity := fs.String("identity-file", "", "private SSH identity file")
	knownHosts := fs.String("known-hosts", "", "strict SSH known-hosts file")
	port := fs.Int("port", 22, "Raspberry Pi SSH port")
	jsonOutput := fs.Bool("json", false, "emit machine-readable status")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("companion status uses the configured SERVERS reservation and does not accept an address")
	}
	if *port < 1 || *port > 65535 {
		return fmt.Errorf("SSH port %d is outside 1-65535", *port)
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	reservation, ok := model.CompanionReservation(s.Companion)
	if !ok {
		return errors.New("companion is not configured; run boetticher companion add --mac MAC first")
	}
	address := reservation.Address
	if *identity == "" {
		*identity = s.SSHIdentityFile
	}
	if *identity == "" {
		*identity = filepath.Join(model.ExpandUserPath("~"), ".ssh", "id_ed25519")
	}
	*identity = model.ExpandUserPath(*identity)
	if *knownHosts == "" {
		*knownHosts = filepath.Join(*siteDir, "generated", "ssh", "companion_known_hosts")
	}
	*knownHosts = model.ExpandUserPath(*knownHosts)
	if err := validateKioskSSHInputs(*identity, *knownHosts, false); err != nil {
		return err
	}
	if _, err := sshconfig.ReadHostKey(*knownHosts, model.CompanionHostname); err != nil {
		return fmt.Errorf("refusing companion status without an enrolled host key: %w", err)
	}
	platformKnownHosts := deploymentKnownHosts(*siteDir)
	if err := validateKioskSSHInputs(*identity, platformKnownHosts, false); err != nil {
		return err
	}
	sshContent, err := sshconfig.RenderCompanion(s, *user, *identity, platformKnownHosts, *knownHosts, *port)
	if err != nil {
		return err
	}
	workspace, err := os.MkdirTemp("", ".boetticher-companion-status-*")
	if err != nil {
		return fmt.Errorf("create temporary companion status workspace: %w", err)
	}
	defer os.RemoveAll(workspace)
	sshPath := filepath.Join(workspace, "ssh.conf")
	if err := os.WriteFile(sshPath, []byte(sshContent), 0600); err != nil {
		return fmt.Errorf("write temporary companion status SSH configuration: %w", err)
	}
	runner := companionStatusSSHRunner(sshPath)
	statusOutput, runErr := runner.Run(context.Background(), address, *user, "/usr/local/libexec/boetticher-companion status")
	var snapshot companion.Snapshot
	if err := json.Unmarshal(statusOutput, &snapshot); err != nil {
		return fmt.Errorf("read Companion status (setup may be required): %w", errors.Join(err, runErr))
	}
	values := map[string]string{}
	for name, at := range map[string]time.Time{"display": snapshot.RenderedAt, "streamdeck": snapshot.DeckAt, "blinkt": snapshot.BlinktAt} {
		values[name] = "inactive"
		if time.Since(at) < 10*time.Second {
			values[name] = "active"
		}
	}
	for _, item := range snapshot.Items {
		if item.ID == "agent" {
			values["pulse_agent"] = item.Status
		}
	}
	if *jsonOutput {
		if err := json.NewEncoder(out).Encode(map[string]any{"address": address, "services": values, "capabilities": snapshot}); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(out, "Companion target: %s@%s:%d\n", *user, address, *port)
		for _, item := range append(snapshot.Items, snapshot.Modules...) {
			result := "FAIL"
			if item.Status == companion.Healthy || item.Status == companion.Disabled {
				result = "PASS"
			}
			fmt.Fprintf(out, "%-20s %s  %s\n", item.Label, result, item.Reason)
		}
	}
	return errors.Join(companion.Check(snapshot), runErr)
}

func companionStatusSSHRunner(configPath string) proxmox.SSHRunner {
	return proxmox.SSHRunner{ConfigFile: configPath, HostAlias: "boetticher-companion", HostKeyAlias: model.CompanionHostname}
}

func companionStreamDeckBinary(siteDir string, dryRun bool) (string, error) {
	if dryRun {
		return filepath.Join(siteDir, "generated", "release", filepath.FromSlash(artifacts.CompanionStreamDeckPath)), nil
	}
	path, err := artifacts.ResolveImportedCompanion(siteDir)
	if err != nil {
		return "", err
	}
	return path, nil
}

func normalizeCompanionMigrationArgs(args []string) ([]string, error) {
	valueFlags := map[string]bool{
		"--site":         true,
		"-site":          true,
		"--age-identity": true,
		"-age-identity":  true,
		"--proxmox-ca":   true,
		"-proxmox-ca":    true,
	}
	var normalized []string
	var addresses []string
	for index := 0; index < len(args); index++ {
		arg := args[index]
		flagName := arg
		if equals := strings.IndexByte(flagName, '='); equals >= 0 {
			flagName = flagName[:equals]
		}
		if valueFlags[flagName] && !strings.ContainsRune(arg, '=') && index+1 < len(args) {
			normalized = append(normalized, arg, args[index+1])
			index++
			continue
		}
		if !strings.HasPrefix(arg, "-") && sshconfig.ValidateBootstrapAddress(arg) == nil {
			addresses = append(addresses, arg)
			continue
		}
		normalized = append(normalized, arg)
	}
	if len(addresses) != 1 {
		return nil, errors.New("one legacy Proxmox IPv4 address is required")
	}
	return append(normalized, addresses[0]), nil
}

func validateKioskSSHInputs(identity, knownHosts string, dryRun bool) error {
	if identity == "" || knownHosts == "" {
		return errors.New("SSH identity and known-hosts paths are required")
	}
	if !dryRun {
		info, err := os.Lstat(identity)
		if err != nil {
			return fmt.Errorf("read SSH identity file: %w", err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("SSH identity file must be a regular file restricted to its owner")
		}
		if err := pathguard.ValidateNoSymlinkComponents(knownHosts); err != nil {
			return fmt.Errorf("validate SSH known-hosts path: %w", err)
		}
		if info, err := os.Lstat(knownHosts); err == nil {
			if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
				return errors.New("SSH known-hosts file must be a regular file restricted to its owner")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("read SSH known-hosts file: %w", err)
		}
	}
	return nil
}

func kioskSourceRoot() (string, func(), error) {
	archive, archiveErr := artifacts.BuildEmbeddedCompanionSourceArchive()
	if archiveErr != nil {
		return "", func() {}, fmt.Errorf("resolve embedded companion source: %w", archiveErr)
	}
	workspace, workspaceErr := os.MkdirTemp("", ".boetticher-companion-source-*")
	if workspaceErr != nil {
		return "", func() {}, fmt.Errorf("create embedded companion source workspace: %w", workspaceErr)
	}
	if extractErr := artifacts.ExtractSourceArchiveReader(bytes.NewReader(archive), workspace); extractErr != nil {
		_ = os.RemoveAll(workspace)
		return "", func() {}, fmt.Errorf("extract embedded companion source: %w", extractErr)
	}
	return workspace, func() { _ = os.RemoveAll(workspace) }, nil
}

func kioskCertificateSelector(pulseURL, domain string) (string, error) {
	selector, err := kioskCertificateSelectorJSON(pulseURL, domain)
	if err != nil {
		return "", err
	}
	return "'--auto-select-certificate-for-urls=" + string(selector) + "'", nil
}

func kioskCertificatePolicy(pulseURL, domain string) (string, error) {
	selector, err := kioskCertificateSelectorJSON(pulseURL, domain)
	if err != nil {
		return "", err
	}
	policy, err := json.Marshal([]string{string(selector)})
	if err != nil {
		return "", err
	}
	return string(policy), nil
}

func kioskCertificateSelectorJSON(pulseURL, domain string) ([]byte, error) {
	return json.Marshal(map[string]any{
		"pattern": pulseURL,
		"filter": map[string]any{
			"ISSUER":  map[string]string{"CN": "boetticher Issuing CA"},
			"SUBJECT": map[string]string{"CN": "client-" + kioskClientName + "." + domain},
		},
	})
}

func validateKioskClientCertificate(authority pki.Authority, keyPEM, certPEM, chainPEM, domain string, now time.Time) (pki.ClientCertificate, error) {
	identity, err := tls.X509KeyPair([]byte(chainPEM), []byte(keyPEM))
	if err != nil {
		return pki.ClientCertificate{}, fmt.Errorf("parse kiosk client identity: %w", err)
	}
	request, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "client-" + kioskClientName + "." + domain},
	}, identity.PrivateKey)
	if err != nil {
		return pki.ClientCertificate{}, fmt.Errorf("create kiosk client certificate request: %w", err)
	}
	certificate, err := pki.ValidateClientCertificate(authority, chainPEM, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: request})), kioskClientName, domain, now)
	if err != nil {
		return pki.ClientCertificate{}, fmt.Errorf("validate kiosk client certificate: %w", err)
	}
	if strings.TrimSpace(certificate.CertPEM) != strings.TrimSpace(certPEM) {
		return pki.ClientCertificate{}, errors.New("kiosk client certificate does not match its chain")
	}
	return certificate, nil
}

func ensureKioskClientCertificate(siteDir string, s model.Site, authority pki.Authority) (pki.ClientCertificate, error) {
	now := time.Now().UTC()
	runtimeDir := filepath.Join(site.RuntimeDir(s), "pki", kioskClientName)
	paths := []string{
		filepath.Join(runtimeDir, "client.key.pem"),
		filepath.Join(runtimeDir, "client.crt.pem"),
		filepath.Join(runtimeDir, "chain.crt.pem"),
	}
	existing := make([][]byte, len(paths))
	present := 0
	for index, path := range paths {
		data, err := pathguard.ReadFile(path)
		if err == nil {
			existing[index] = data
			present++
			continue
		}
		if !errors.Is(err, os.ErrNotExist) {
			return pki.ClientCertificate{}, fmt.Errorf("read kiosk PKI runtime: %w", err)
		}
	}
	if present == len(paths) {
		certificate, err := validateKioskClientCertificate(authority, string(existing[0]), string(existing[1]), string(existing[2]), s.Network.Domain, now)
		if err == nil {
			certificate.KeyPEM = string(existing[0])
			certificate.CertPEM = string(existing[1])
			certificate.ChainPEM = string(existing[2])
			return certificate, nil
		}
	}

	certificate, err := pki.IssueClient(authority, kioskClientName, s.Network.Domain, now)
	if err != nil {
		return pki.ClientCertificate{}, fmt.Errorf("issue kiosk client certificate: %w", err)
	}
	if err := publishKioskClientIdentity(runtimeDir, certificate); err != nil {
		return pki.ClientCertificate{}, err
	}
	metadata := fmt.Sprintf("name: %s\nfingerprint: %s\nserial: %s\ncreated_at: %s\n", kioskClientName, certificate.Fingerprint, certificate.Serial, time.Now().UTC().Format(time.RFC3339))
	if err := writePublic(filepath.Join(siteDir, "generated", "pki", kioskClientName+".yaml"), []byte(metadata)); err != nil {
		return pki.ClientCertificate{}, err
	}
	return certificate, nil
}

func publishKioskClientIdentity(runtimeDir string, certificate pki.ClientCertificate) error {
	if err := pathguard.ValidateNoSymlinkComponents(runtimeDir); err != nil {
		return fmt.Errorf("refuse kiosk identity path: %w", err)
	}
	parent := filepath.Dir(runtimeDir)
	if err := pathguard.MkdirAll(parent, 0700); err != nil {
		return fmt.Errorf("create kiosk identity parent: %w", err)
	}
	stage, err := pathguard.MkdirTemp(parent, ".boetticher-kiosk-identity-", 0700)
	if err != nil {
		return fmt.Errorf("stage kiosk identity: %w", err)
	}
	defer func() { _ = pathguard.RemoveAll(stage) }()
	for _, file := range []struct {
		name string
		data string
		mode os.FileMode
	}{
		{name: "client.key.pem", data: certificate.KeyPEM, mode: 0600},
		{name: "client.crt.pem", data: certificate.CertPEM, mode: 0644},
		{name: "chain.crt.pem", data: certificate.ChainPEM, mode: 0644},
	} {
		if err := pathguard.WriteFile(filepath.Join(stage, file.name), []byte(file.data), file.mode); err != nil {
			return fmt.Errorf("stage kiosk identity %s: %w", file.name, err)
		}
	}
	return publishKioskIdentity(runtimeDir, stage)
}

func publishKioskIdentity(runtimeDir, stage string) error {
	if err := pathguard.ValidateNoSymlinkComponents(runtimeDir); err != nil {
		return fmt.Errorf("refuse kiosk identity publication path: %w", err)
	}
	previous := runtimeDir + ".previous"
	if err := pathguard.ValidateNoSymlinkComponents(previous); err != nil {
		return fmt.Errorf("refuse kiosk identity previous path: %w", err)
	}
	if _, err := os.Lstat(runtimeDir); err == nil {
		if err := pathguard.RemoveAll(previous); err != nil {
			return err
		}
		if err := pathguard.Rename(runtimeDir, previous); err != nil {
			return err
		}
		if err := pathguard.Rename(stage, runtimeDir); err != nil {
			_ = pathguard.Rename(previous, runtimeDir)
			return err
		}
		return pathguard.RemoveAll(previous)
	} else if !os.IsNotExist(err) {
		return err
	}
	return pathguard.Rename(stage, runtimeDir)
}
