package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
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
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/pathguard"
	"github.com/gofastercloud/boetticher/internal/pki"
	"github.com/gofastercloud/boetticher/internal/proxmox"
	"github.com/gofastercloud/boetticher/internal/site"
	"github.com/gofastercloud/boetticher/internal/sshconfig"
	"github.com/gofastercloud/boetticher/internal/streamdeck"
)

const kioskClientName = "lab-display-01-kiosk"
const companionStreamDeckIdentity = "companion-streamdeck"

func runCompanion(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher companion setup|status|migrate ADDRESS [options]")
	}
	switch args[0] {
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

func runCompanionMigrate(args []string, out io.Writer) error {
	args, err := normalizeKioskArgs(args)
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
	fmt.Fprintln(out, "Result: StreamDeck will be a companion capability; no Proxmox guest will be recreated")
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
	if err := site.ApplyLegacyStreamDeckMigration(*siteDir, config, filteredRetained); err != nil {
		return fmt.Errorf("commit companion migration state: %w", err)
	}
	if err := writeModelProjections(*siteDir, migrated); err != nil {
		return fmt.Errorf("refresh migrated projections: %w; migration state is committed and the old guest was not removed", err)
	}
	rootRunner := proxmoxRootSSHRunner(migrated, *siteDir)
	if _, err := rootRunner.RunArgs(context.Background(), migrated.BootstrapAddress, "root", proxmox.LegacyStreamDeckUSBRemovalArgs()); err != nil {
		return fmt.Errorf("remove exact legacy StreamDeck USB mapping before guest removal: %w; migration state is committed and the old guest was not removed", err)
	}
	if err := proxmox.RemoveLegacyStreamDeck(context.Background(), client, node); err != nil {
		return fmt.Errorf("remove legacy StreamDeck guest: %w; migration state is committed", err)
	}
	if present {
		fmt.Fprintln(out, "Legacy guest: PASS exact owned StreamDeck LXC removed and verified absent")
	} else {
		fmt.Fprintln(out, "Legacy guest: PASS exact StreamDeck LXC was already absent")
	}
	fmt.Fprintf(out, "Companion migration: PASS %s migrated; unrelated USB mappings were not selected\n", address)
	return nil
}

func runCompanionSetup(args []string, out io.Writer) error {
	args, err := normalizeKioskArgs(args)
	if err != nil {
		return err
	}
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
	if fs.NArg() != 1 {
		return errors.New("one Raspberry Pi IPv4 address is required")
	}
	address := fs.Arg(0)
	if err := sshconfig.ValidateBootstrapAddress(address); err != nil {
		return err
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
	sshContent, err := sshconfig.RenderDirect(address, *user, *identity, *knownHosts, *port)
	if err != nil {
		return err
	}
	sourceRoot, cleanupSource, err := kioskSourceRoot()
	if err != nil {
		return err
	}
	defer cleanupSource()
	pulseURL := "https://monitor." + s.Network.Domain
	certificateSelector, err := kioskCertificateSelector(pulseURL, s.Network.Domain)
	if err != nil {
		return err
	}
	certificatePolicy, err := kioskCertificatePolicy(pulseURL, s.Network.Domain)
	if err != nil {
		return err
	}
	streamDeckBinary := ""
	fmt.Fprintf(out, "Companion target: %s@%s:%d\n", *user, address, *port)
	fmt.Fprintf(out, "Pulse URL: %s\n", pulseURL)
	fmt.Fprintf(out, "Companion source: %s\n", filepath.Join(sourceRoot, "pi", "kiosk"))
	fmt.Fprintf(out, "Capabilities: display=%t streamdeck=%t pulse-agent=%t\n", capabilities.Display, capabilities.StreamDeck, capabilities.PulseAgent)
	fmt.Fprintf(out, "Host-key trust: %s\n", *knownHosts)
	if *dryRun {
		fmt.Fprintln(out, "Companion setup: PASS dry-run only; no PKI, site, SSH, or remote changes made")
		return nil
	}
	if !*confirm {
		return errors.New("companion setup changes the remote Pi and local PKI runtime; rerun with --confirm")
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
	if _, err := sshconfig.ReadHostKey(*knownHosts, address); err != nil {
		if *hostKey == "" {
			return fmt.Errorf("refusing unknown Raspberry Pi host key: %w; enroll an independently verified key with --host-key", err)
		}
		if err := os.MkdirAll(filepath.Dir(*knownHosts), 0700); err != nil {
			return fmt.Errorf("create SSH known-hosts directory: %w", err)
		}
		if err := sshconfig.AddKnownHostKey(*knownHosts, address, *hostKey); err != nil {
			return err
		}
	} else if *hostKey != "" {
		if err := sshconfig.AddKnownHostKey(*knownHosts, address, *hostKey); err != nil {
			return err
		}
	}

	var pulseAgentToken string
	if capabilities.PulseAgent {
		pulseAgentToken, err = site.LoadPlatformSecret(*siteDir, s, *ageIdentity, "pulse_agent_token")
		if err != nil {
			return fmt.Errorf("load encrypted Pulse agent token (run boetticher deploy first): %w", err)
		}
	}
	var pulseReadToken string
	var streamDeckCertificate pki.ClientCertificate
	if capabilities.StreamDeck {
		pulseReadToken, err = site.LoadPlatformSecret(*siteDir, s, *ageIdentity, "pulse_api_token")
		if err != nil {
			return fmt.Errorf("load encrypted Pulse read token (run boetticher deploy first): %w", err)
		}
	}
	authority, err := site.LoadAuthority(*siteDir, s, *ageIdentity)
	if err != nil {
		return fmt.Errorf("load Boetticher PKI authority: %w", err)
	}
	if !capabilities.Display {
		if err := revokeAndRemoveCompanionCertificate(*siteDir, s, kioskClientName, out); err != nil {
			return fmt.Errorf("revoke disabled kiosk identity: %w", err)
		}
	}
	if !capabilities.StreamDeck {
		if err := revokeAndRemoveCompanionCertificate(*siteDir, s, companionStreamDeckIdentity, out); err != nil {
			return fmt.Errorf("revoke disabled StreamDeck identity: %w", err)
		}
	}
	certificate := pki.ClientCertificate{}
	if capabilities.Display {
		certificate, err = ensureKioskClientCertificate(*siteDir, s, authority)
		if err != nil {
			return err
		}
	}
	if capabilities.StreamDeck {
		streamDeckCertificate, err = ensureCompanionStreamDeckCertificate(*siteDir, s, authority)
		if err != nil {
			return err
		}
	}
	password := ""
	if capabilities.Display {
		password, err = kioskImportPassword()
		if err != nil {
			return fmt.Errorf("generate temporary kiosk import password: %w", err)
		}
	}
	variables, err := json.MarshalIndent(map[string]any{
		"kiosk_become":                     *user != "root",
		"kiosk_display_enabled":            capabilities.Display,
		"kiosk_streamdeck_enabled":         capabilities.StreamDeck,
		"kiosk_pulse_agent_enabled":        capabilities.PulseAgent,
		"kiosk_source_dir":                 filepath.Join(sourceRoot, "pi", "kiosk"),
		"kiosk_pulse_url":                  pulseURL,
		"kiosk_pulse_agent_hostname":       kioskClientName,
		"kiosk_pulse_agent_version":        model.PulseAgentVersion,
		"kiosk_pulse_agent_release_url":    model.PulseAgentARM64ReleaseURL,
		"kiosk_pulse_agent_release_sha256": model.PulseAgentARM64ReleaseSHA256,
		"kiosk_pulse_agent_token":          pulseAgentToken,
		"streamdeck_binary":                streamDeckBinary,
		"streamdeck_pulse_token":           pulseReadToken,
		"streamdeck_client_identity":       companionStreamDeckIdentity,
		"streamdeck_vendor_id":             streamdeck.DefaultVendorID,
		"streamdeck_product_id":            streamdeck.DefaultProductID,
		"streamdeck_model":                 streamdeck.DefaultModel,
		"streamdeck_serial":                "",
		"streamdeck_client_key_pem":        streamDeckCertificate.KeyPEM,
		"streamdeck_client_cert_pem":       streamDeckCertificate.ChainPEM,
		"kiosk_certificate_selector":       certificateSelector,
		"kiosk_certificate_policy":         certificatePolicy,
		"kiosk_client_subject":             "client-" + kioskClientName + "." + s.Network.Domain,
		"kiosk_client_nickname":            "Boetticher Pulse kiosk",
		"kiosk_client_key_pem":             certificate.KeyPEM,
		"kiosk_client_cert_pem":            certificate.CertPEM,
		"kiosk_root_ca_pem":                authority.RootCertPEM,
		"kiosk_issuing_ca_pem":             authority.IssuingCertPEM,
		"kiosk_pkcs12_password":            password,
		"kiosk_client_certificate_serial":  certificate.Serial,
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
	inventory := "# Temporary Boetticher companion inventory.\n[kiosk]\nboetticher-companion ansible_host=" + address + "\n\n[kiosk:vars]\nansible_python_interpreter=/usr/bin/python3\n"
	if err := os.WriteFile(inventoryPath, []byte(inventory), 0600); err != nil {
		return fmt.Errorf("write temporary companion inventory: %w", err)
	}
	if err := os.WriteFile(sshConfigPath, []byte(sshContent), 0600); err != nil {
		return fmt.Errorf("write temporary companion SSH configuration: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if _, err := ansible.RunExternal(ctx, playbook, inventoryPath, variables, sshConfigPath, *user); err != nil {
		return fmt.Errorf("configure Raspberry Pi companion: %w", err)
	}
	fmt.Fprintf(out, "Companion setup: PASS %s configured; capabilities display=%t streamdeck=%t pulse-agent=%t\n", address, capabilities.Display, capabilities.StreamDeck, capabilities.PulseAgent)
	return nil
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
	args, err := normalizeKioskArgs(args)
	if err != nil {
		return err
	}
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
	if fs.NArg() != 1 {
		return errors.New("one Raspberry Pi IPv4 address is required")
	}
	address := fs.Arg(0)
	if err := sshconfig.ValidateBootstrapAddress(address); err != nil {
		return err
	}
	if *port < 1 || *port > 65535 {
		return fmt.Errorf("SSH port %d is outside 1-65535", *port)
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
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
	if _, err := sshconfig.ReadHostKey(*knownHosts, address); err != nil {
		return fmt.Errorf("refusing companion status without an enrolled host key: %w", err)
	}
	sshContent, err := sshconfig.RenderDirect(address, *user, *identity, *knownHosts, *port)
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
	runner := proxmox.SSHRunner{ConfigFile: sshPath, HostAlias: "boetticher-companion", HostKeyAlias: "boetticher-companion"}
	statusOutput, runErr := runner.Run(context.Background(), address, *user, "for unit in boetticher-streamdeck.service pulse-kiosk.service pulse-agent.service; do printf '%s ' \"$unit\"; systemctl is-active \"$unit\" 2>/dev/null || true; done")
	if runErr != nil {
		return fmt.Errorf("read companion service status: %w", runErr)
	}
	values := map[string]string{"streamdeck": "unknown", "display": "unknown", "pulse_agent": "unknown"}
	for _, line := range strings.Split(strings.TrimSpace(string(statusOutput)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		switch fields[0] {
		case "boetticher-streamdeck.service":
			values["streamdeck"] = fields[1]
		case "pulse-kiosk.service":
			values["display"] = fields[1]
		case "pulse-agent.service":
			values["pulse_agent"] = fields[1]
		}
	}
	if *jsonOutput {
		return json.NewEncoder(out).Encode(map[string]any{"address": address, "services": values})
	}
	fmt.Fprintf(out, "Companion target: %s@%s:%d\n", *user, address, *port)
	fmt.Fprintf(out, "Display: %s\nStreamDeck: %s\nPulse agent: %s\n", values["display"], values["streamdeck"], values["pulse_agent"])
	return nil
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

func normalizeKioskArgs(args []string) ([]string, error) {
	valueFlags := map[string]bool{
		"--site":          true,
		"-site":           true,
		"--age-identity":  true,
		"-age-identity":   true,
		"--user":          true,
		"-user":           true,
		"--identity-file": true,
		"-identity-file":  true,
		"--known-hosts":   true,
		"-known-hosts":    true,
		"--host-key":      true,
		"-host-key":       true,
		"--port":          true,
		"-port":           true,
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
		return nil, errors.New("one Raspberry Pi IPv4 address is required")
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

func kioskImportPassword() (string, error) {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
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

func ensureCompanionStreamDeckCertificate(siteDir string, s model.Site, authority pki.Authority) (pki.ClientCertificate, error) {
	now := time.Now().UTC()
	runtimeDir := filepath.Join(site.RuntimeDir(s), "pki", companionStreamDeckIdentity)
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
			return pki.ClientCertificate{}, fmt.Errorf("read companion StreamDeck PKI runtime: %w", err)
		}
	}
	if present == len(paths) {
		certificate, err := validateCachedServiceClientCertificate(authority, string(existing[0]), string(existing[1]), string(existing[2]), companionStreamDeckIdentity, now)
		if err == nil {
			return certificate, nil
		}
	}
	certificate, err := pki.IssueServiceClient(authority, companionStreamDeckIdentity, now)
	if err != nil {
		return pki.ClientCertificate{}, fmt.Errorf("issue companion StreamDeck client certificate: %w", err)
	}
	if err := publishKioskClientIdentity(runtimeDir, certificate); err != nil {
		return pki.ClientCertificate{}, err
	}
	metadata := fmt.Sprintf("name: %s\nfingerprint: %s\nserial: %s\ncreated_at: %s\n", companionStreamDeckIdentity, certificate.Fingerprint, certificate.Serial, now.Format(time.RFC3339))
	if err := writePublic(filepath.Join(siteDir, "generated", "pki", companionStreamDeckIdentity+".yaml"), []byte(metadata)); err != nil {
		return pki.ClientCertificate{}, err
	}
	return certificate, nil
}

func validateCachedServiceClientCertificate(authority pki.Authority, keyPEM, certPEM, chainPEM, identity string, now time.Time) (pki.ClientCertificate, error) {
	pair, err := tls.X509KeyPair([]byte(chainPEM), []byte(keyPEM))
	if err != nil {
		return pki.ClientCertificate{}, err
	}
	request, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: identity}}, pair.PrivateKey)
	if err != nil {
		return pki.ClientCertificate{}, err
	}
	requestPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: request})
	certificate, err := pki.ValidateServiceClientCertificate(authority, chainPEM, string(requestPEM), identity, now)
	if err != nil {
		return pki.ClientCertificate{}, err
	}
	if strings.TrimSpace(certificate.CertPEM) != strings.TrimSpace(certPEM) {
		return pki.ClientCertificate{}, errors.New("cached companion StreamDeck certificate does not match its chain")
	}
	certificate.KeyPEM = keyPEM
	certificate.CertPEM = certPEM
	certificate.ChainPEM = chainPEM
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
