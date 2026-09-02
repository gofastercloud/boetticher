package cli

import (
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
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/pathguard"
	"github.com/gofastercloud/boetticher/internal/pki"
	"github.com/gofastercloud/boetticher/internal/site"
	"github.com/gofastercloud/boetticher/internal/sshconfig"
)

const kioskClientName = "lab-display-01-kiosk"

func runKiosk(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher kiosk setup ADDRESS [options]")
	}
	if args[0] != "setup" {
		return fmt.Errorf("unknown kiosk command %q", args[0])
	}
	return runKioskSetup(args[1:], out)
}

func runKioskSetup(args []string, out io.Writer) error {
	args, err := normalizeKioskArgs(args)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("kiosk setup", flag.ContinueOnError)
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
	if *identity == "" {
		*identity = s.SSHIdentityFile
	}
	if *identity == "" {
		*identity = filepath.Join(model.ExpandUserPath("~"), ".ssh", "id_ed25519")
	}
	*identity = model.ExpandUserPath(*identity)
	if *knownHosts == "" {
		*knownHosts = filepath.Join(*siteDir, "generated", "ssh", "kiosk_known_hosts")
	}
	*knownHosts = model.ExpandUserPath(*knownHosts)
	if err := validateKioskSSHInputs(*identity, *knownHosts, *dryRun); err != nil {
		return err
	}
	sshContent, err := sshconfig.RenderDirect(address, *user, *identity, *knownHosts, *port)
	if err != nil {
		return err
	}
	sourceRoot, err := kioskSourceRoot()
	if err != nil {
		return err
	}
	pulseURL := "https://monitor." + s.Network.Domain
	certificateSelector, err := kioskCertificateSelector(pulseURL, s.Network.Domain)
	if err != nil {
		return err
	}
	certificatePolicy, err := kioskCertificatePolicy(pulseURL, s.Network.Domain)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Kiosk target: %s@%s:%d\n", *user, address, *port)
	fmt.Fprintf(out, "Pulse URL: %s\n", pulseURL)
	fmt.Fprintf(out, "Kiosk source: %s\n", filepath.Join(sourceRoot, "pi", "kiosk"))
	fmt.Fprintf(out, "Host-key trust: %s\n", *knownHosts)
	if *dryRun {
		fmt.Fprintln(out, "Kiosk setup: PASS dry-run only; no PKI, site, SSH, or remote changes made")
		return nil
	}
	if !*confirm {
		return errors.New("kiosk setup changes the remote Pi and local PKI runtime; rerun with --confirm")
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

	pulseAgentToken, err := site.LoadPlatformSecret(*siteDir, s, *ageIdentity, "pulse_agent_token")
	if err != nil {
		return fmt.Errorf("load encrypted Pulse agent token (run boetticher deploy first): %w", err)
	}
	authority, err := site.LoadAuthority(*siteDir, s, *ageIdentity)
	if err != nil {
		return fmt.Errorf("load Boetticher PKI authority: %w", err)
	}
	certificate, err := ensureKioskClientCertificate(*siteDir, s, authority)
	if err != nil {
		return err
	}
	password, err := kioskImportPassword()
	if err != nil {
		return fmt.Errorf("generate temporary kiosk import password: %w", err)
	}
	variables, err := json.MarshalIndent(map[string]any{
		"kiosk_become":                     *user != "root",
		"kiosk_source_dir":                 filepath.Join(sourceRoot, "pi", "kiosk"),
		"kiosk_pulse_url":                  pulseURL,
		"kiosk_pulse_agent_hostname":       kioskClientName,
		"kiosk_pulse_agent_version":        model.PulseAgentVersion,
		"kiosk_pulse_agent_release_url":    model.PulseAgentARM64ReleaseURL,
		"kiosk_pulse_agent_release_sha256": model.PulseAgentARM64ReleaseSHA256,
		"kiosk_pulse_agent_token":          pulseAgentToken,
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
		return fmt.Errorf("encode kiosk Ansible variables: %w", err)
	}
	variables = append(variables, '\n')

	workspace, err := os.MkdirTemp("", ".boetticher-kiosk-*")
	if err != nil {
		return fmt.Errorf("create temporary kiosk Ansible workspace: %w", err)
	}
	defer os.RemoveAll(workspace)
	inventoryPath := filepath.Join(workspace, "inventory.ini")
	sshConfigPath := filepath.Join(workspace, "ssh.conf")
	playbook := filepath.Join(sourceRoot, "ansible", "kiosk.yml")
	inventory := "# Temporary Boetticher Raspberry Pi kiosk inventory.\n[kiosk]\nboetticher-kiosk ansible_host=" + address + "\n\n[kiosk:vars]\nansible_python_interpreter=/usr/bin/python3\n"
	if err := os.WriteFile(inventoryPath, []byte(inventory), 0600); err != nil {
		return fmt.Errorf("write temporary kiosk inventory: %w", err)
	}
	if err := os.WriteFile(sshConfigPath, []byte(sshContent), 0600); err != nil {
		return fmt.Errorf("write temporary kiosk SSH configuration: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if _, err := ansible.RunExternal(ctx, playbook, inventoryPath, variables, sshConfigPath, *user); err != nil {
		return fmt.Errorf("configure Raspberry Pi kiosk: %w", err)
	}
	fmt.Fprintf(out, "Kiosk setup: PASS %s configured; client identity %s\n", address, kioskClientName)
	return nil
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

func kioskSourceRoot() (string, error) {
	root, err := applianceBuildSourceRoot()
	if err != nil {
		return "", fmt.Errorf("resolve kiosk Ansible source: %w", err)
	}
	for _, relative := range []string{
		"ansible/kiosk.yml",
		"ansible/roles/kiosk/tasks/main.yml",
		"ansible/roles/kiosk/templates/pulse-kiosk.service.j2",
		"pi/kiosk/visualizer/index.html",
		"pi/kiosk/libexec/pulse-kiosk-stats",
		"pi/kiosk/pulse-refresh-extension/manifest.json",
		"pi/kiosk/pulse-refresh-extension/reload.js",
		"pi/kiosk/systemd/pulse-kiosk-stats.service",
		"pi/kiosk/systemd/pulse-kiosk-stats.timer",
	} {
		if _, err := os.Stat(filepath.Join(root, relative)); err != nil {
			return "", fmt.Errorf("kiosk source is incomplete at %s: %w", filepath.Join(root, relative), err)
		}
	}
	return root, nil
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
	if s.BootstrapAddress != "" {
		if err := rebuildPortal(siteDir, s); err != nil {
			return pki.ClientCertificate{}, err
		}
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
