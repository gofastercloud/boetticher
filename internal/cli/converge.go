package cli

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	aiopsmodel "github.com/gofastercloud/boetticher/internal/aiops"
	"github.com/gofastercloud/boetticher/internal/ansible"
	"github.com/gofastercloud/boetticher/internal/appliance"
	"github.com/gofastercloud/boetticher/internal/backup"
	"github.com/gofastercloud/boetticher/internal/dns"
	"github.com/gofastercloud/boetticher/internal/firewall"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
	"github.com/gofastercloud/boetticher/internal/pki"
	"github.com/gofastercloud/boetticher/internal/proxmox"
	"github.com/gofastercloud/boetticher/internal/pulse"
	"github.com/gofastercloud/boetticher/internal/site"
	"github.com/gofastercloud/boetticher/internal/storage"
)

func runDeploy(args []string, out interface{ Write([]byte) (int, error) }) error {
	fs := flag.NewFlagSet("deploy", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	proxmoxCA := fs.String("proxmox-ca", "", "Proxmox API CA PEM file")
	insecure := fs.Bool("insecure", false, "explicitly allow self-signed Proxmox API TLS")
	dryRun := fs.Bool("dry-run", false, "render and validate policy without connecting")
	confirm := fs.Bool("confirm", false, "confirm destructive appliance replacement or purge actions")
	if err := fs.Parse(args); err != nil {
		return err
	}
	_ = confirm // replacement confirmation is enforced by the shared provider plan
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	firewallPlan, err := firewall.PlanFromSite(s)
	if err != nil {
		return err
	}
	if *dryRun {
		fmt.Fprintf(out, "Deployment plan: PASS model %s\n", firewallPlan.ModelRevision)
		fmt.Fprintf(out, "  Mode: %s\n  Engine: %s\n  DHCP subnets: %d\n  Policy rules: %d\n", firewallPlan.Mode, firewallPlan.Engine, len(firewallPlan.DHCP), len(firewallPlan.Rules))
		if s.Gateway.Mode == model.GatewayModeManaged {
			ruleset, renderErr := firewall.RenderNFT(firewallPlan)
			if renderErr != nil {
				return renderErr
			}
			if err := firewall.ValidateNFT(ruleset); err != nil {
				return err
			}
			fmt.Fprintln(out, "  nftables: valid generated ruleset")
		} else {
			fmt.Fprintln(out, "  External contract: generated")
		}
		fmt.Fprintln(out, "  Destructive actions: NOT RUN (dry-run)")
		if plan, planErr := proxmox.PlanFromSite(s); planErr == nil {
			qualified, qualifyErr := proxmox.ResolveQualifiedArtifacts(*siteDir, plan, true)
			if qualifyErr != nil {
				fmt.Fprintf(out, "  Artifact qualification: HOLD (%v)\n", qualifyErr)
			} else {
				plan = qualified
				fmt.Fprintln(out, "  Artifact qualification: PASS (all selected artifacts qualified)")
			}
			fmt.Fprintln(out, "  Appliances:")
			for _, guest := range plan.Guests {
				fmt.Fprintf(out, "    %s  %s  %s  definition=%s\n", guest.Name, guest.Artifact.Name, artifactQualificationStatus(guest.Artifact), guest.Artifact.DefinitionSHA256)
				for _, volume := range guest.Volumes {
					fmt.Fprintf(out, "    volume %s -> %s (%s, backup=%t)\n", volume.Name, volume.MountPath, volume.Placement, volume.Backup)
				}
			}
		}
		return nil
	}
	ansibleRoot, err := applianceBuildSourceRoot()
	if err != nil {
		return fmt.Errorf("resolve Ansible playbook source: %w", err)
	}
	ansiblePlaybook := filepath.Join(ansibleRoot, "ansible", "site.yml")
	if err := writeModelProjections(*siteDir, s); err != nil {
		return err
	}
	backupPlan, err := backup.PlanFromSite(s)
	if err != nil {
		return err
	}
	storagePlan, err := storage.PlanFromSite(s)
	if err != nil {
		return err
	}
	proxmoxPlan, err := proxmox.PlanFromSite(s)
	if err != nil {
		return err
	}
	proxmoxPlan, err = proxmox.ResolveQualifiedArtifacts(*siteDir, proxmoxPlan, true)
	if err != nil {
		return err
	}
	operatorPublicKey, err := loadBootstrapOperatorKey(*siteDir)
	if err != nil {
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
	credentialBindings, err := deploymentCredentialBindings(s)
	if err != nil {
		return err
	}
	portalSourceDir, err := absolutePortalSourceDir(*siteDir)
	if err != nil {
		return err
	}
	runtimeVariables["portal_source_dir"] = portalSourceDir
	runtimeVariables["boetticher_appliance_artifact"] = true
	// Agent installation is enabled only in the post-Pulse bootstrap pass,
	// after the scoped report token and encrypted credential projection exist.
	runtimeVariables["pulse_agent_install_enabled"] = false
	runtimeVariables["streamdeck_token_install_enabled"] = false
	monitoringEnabled := modules.IsEnabled(s, "monitoring")
	aiopsEnabled := modules.IsEnabled(s, "aiops")
	secretValues := map[string]string{}
	if s.Gateway.Mode == model.GatewayModeManaged {
		ddnsTSIG, loadErr := site.LoadDDNSTSIG(*siteDir, s, *ageIdentity)
		if loadErr != nil {
			return fmt.Errorf("load encrypted DDNS TSIG material: %w", loadErr)
		}
		secretValues["firewall-ddns-tsig"] = ddnsTSIG
	}
	if s.Gateway.Mode == model.GatewayModeManaged {
		ruleset, renderErr := firewall.RenderNFT(firewallPlan)
		if renderErr != nil {
			return renderErr
		}
		runtimeVariables["firewall_ruleset"] = ruleset
	}
	authority, err := site.LoadAuthority(*siteDir, s, *ageIdentity)
	if err != nil {
		return fmt.Errorf("load platform CA chain: %w", err)
	}
	var pulseAdminPassword string
	if monitoringEnabled {
		var loadErr error
		pulseAdminPassword, loadErr = site.LoadPlatformSecret(*siteDir, s, *ageIdentity, "pulse_admin_password")
		if loadErr != nil {
			return fmt.Errorf("load encrypted Pulse administrative password: %w", loadErr)
		}
		secretValues["pulse_admin_password"] = pulseAdminPassword
	}
	activeCredentialBindings := make([]deploymentCredential, 0, len(credentialBindings))
	for _, binding := range credentialBindings {
		if binding.Guest == "lab-aiops-01" {
			// Pulse-scoped tokens and the webhook secret are reconciled only
			// after Pulse and AI Router pass their live qualification gates.
			continue
		}
		if _, alreadyLoaded := secretValues[binding.SecretKey]; alreadyLoaded {
			activeCredentialBindings = append(activeCredentialBindings, binding)
			continue
		}
		value, loadErr := site.LoadPlatformSecret(*siteDir, s, *ageIdentity, binding.SecretKey)
		if loadErr != nil {
			if binding.SecretKey == "tailscale_auth_key" && errors.Is(loadErr, site.ErrPlatformSecretMissing) {
				// A retained, valid Tailscale state file is the durable node
				// identity. The runtime helper will use it without a fresh key;
				// a missing/invalid state fails closed at service start.
				continue
			}
			return fmt.Errorf("load encrypted %s credential: %w", binding.SecretKey, loadErr)
		}
		activeCredentialBindings = append(activeCredentialBindings, binding)
		secretValues[binding.SecretKey] = value
	}
	credentialBindings = activeCredentialBindings
	runtimeVariables["credential_dropins"], err = credentialDropIns(credentialBindings)
	if err != nil {
		return err
	}
	runtimeVariables["client_ca_pem"] = authority.RootCertPEM + authority.IssuingCertPEM
	runtimeVariables["pulse_server_ca_pem"] = authority.RootCertPEM + authority.IssuingCertPEM
	if *proxmoxCA != "" {
		proxmoxCAPEM, readErr := os.ReadFile(*proxmoxCA)
		if readErr != nil {
			return fmt.Errorf("read Proxmox API CA file: %w", readErr)
		}
		runtimeVariables["proxmox_ca_pem"] = string(proxmoxCAPEM)
	}
	inventoryPath := filepath.Join(*siteDir, "generated", "ansible", "inventory.ini")
	csrDir := filepath.Join(site.RuntimeDir(s), "pki")
	if err := os.MkdirAll(csrDir, 0700); err != nil {
		return fmt.Errorf("create controller PKI runtime directory: %w", err)
	}
	runtimeVariables["pki_bootstrap_phase"] = true
	runtimeVariables["pki_csr_output_dir"] = csrDir
	variables, err = json.MarshalIndent(runtimeVariables, "", "  ")
	if err != nil {
		return err
	}
	variables = append(variables, '\n')
	proxmoxPlan.OperatorPublicKey = operatorPublicKey
	if s.Gateway.Mode == model.GatewayModeManaged {
		for _, guest := range proxmoxPlan.Guests {
			if guest.Name != "lab-fw-01" {
				continue
			}
			cloudInit, renderErr := proxmox.RenderFirewallCloudInitWithKey(guest, operatorPublicKey)
			if renderErr != nil {
				return fmt.Errorf("render firewall first-boot cloud-init: %w", renderErr)
			}
			proxmoxPlan.CloudInitFiles = cloudInit
			break
		}
	}
	rootRunner := proxmoxRootSSHRunner(s, *siteDir)
	if err := proxmox.WaitForSSH(context.Background(), rootRunner, s.BootstrapAddress, "root", 1, 0); err != nil {
		return fmt.Errorf("HOLD: temporary root deployment authority is unavailable; rerun bootstrap or recovery: %w", err)
	}
	proxmoxClient, _, err := loadProxmoxClientWithSnippetUser(*siteDir, s, *ageIdentity, *proxmoxCA, *insecure, "root")
	if err != nil {
		return fmt.Errorf("load Proxmox client for platform deployment: %w", err)
	}
	node, err := proxmoxClient.SingleNode(context.Background())
	if err != nil {
		return fmt.Errorf("resolve live Proxmox node: %w", err)
	}
	proxmoxPlan.Node = node
	var pulseProxmoxToken string
	if monitoringEnabled {
		pulseProxmoxToken, err = site.LoadPlatformSecret(*siteDir, s, *ageIdentity, "pulse_proxmox_token")
		if errors.Is(err, site.ErrPlatformSecretMissing) {
			pulseProxmoxToken, err = proxmox.CreatePulseMonitoringCredentials(context.Background(), rootRunner, s.BootstrapAddress, "root")
			if err != nil {
				return err
			}
			if err := site.StorePlatformSecret(*siteDir, s, *ageIdentity, "pulse_proxmox_token", pulseProxmoxToken); err != nil {
				return fmt.Errorf("store encrypted Pulse Proxmox token: %w", err)
			}
		} else if err != nil {
			return fmt.Errorf("load encrypted Pulse Proxmox token: %w", err)
		}
	}
	proxmoxPlan.DestructiveConfirmed = *confirm
	if backupPlan.StorageTarget == backup.DedicatedStorageID {
		if err := proxmoxClient.EnsureLVMThinStorage(context.Background(), storage.GuestStorageID, storage.VolumeGroup, storage.ThinPool); err != nil {
			return fmt.Errorf("ensure dedicated guest storage: %w", err)
		}
		if err := proxmoxClient.EnsureDirectoryStorage(context.Background(), backup.DedicatedStorageID, backup.DedicatedStoragePath); err != nil {
			return fmt.Errorf("ensure dedicated backup storage: %w", err)
		}
	} else if err := proxmoxClient.EnsureDirectoryStorageContent(context.Background(), "local", "/var/lib/vz", []string{"backup", "images", "rootdir", "vztmpl", "snippets"}); err != nil {
		return fmt.Errorf("ensure single-disk Proxmox storage: %w", err)
	}
	if s.Gateway.Mode == model.GatewayModeManaged {
		if err := proxmox.EnsureFirewallVM(context.Background(), proxmoxClient, proxmoxPlan); err != nil {
			return fmt.Errorf("create managed gateway appliance: %w", err)
		}
		if err := proxmoxClient.EnsureVMRunning(context.Background(), proxmoxPlan.Node, model.ProxmoxVMID); err != nil {
			return fmt.Errorf("start managed gateway appliance: %w", err)
		}
	}
	if s.Gateway.Mode == model.GatewayModeManaged {
		firewallRunner := applianceSSHRunner(s, *siteDir, "lab-fw-01")
		if err := proxmox.WaitForSSH(context.Background(), firewallRunner, "10.10.99.1", "root", 30, 2*time.Second); err != nil {
			return fmt.Errorf("HOLD: managed gateway is not reachable before dependent appliances: %w", err)
		}
		if err := verifyFirewallBootstrapNetwork(context.Background(), firewallRunner); err != nil {
			return fmt.Errorf("HOLD: managed gateway bootstrap network is not ready before runtime configuration: %w", err)
		}
		if err := installCredentialsForGuest(context.Background(), firewallRunner, "lab-fw-01", credentialBindings, secretValues); err != nil {
			return fmt.Errorf("install managed gateway credentials: %w", err)
		}
		if err := ansible.RunLimited(context.Background(), ansiblePlaybook, inventoryPath, variables, "lab-fw-01"); err != nil {
			return fmt.Errorf("HOLD: configure managed gateway before dependent appliances: %w", err)
		}
		if err := verifyGatewayReadiness(context.Background(), firewallRunner, "10.10.99.1"); err != nil {
			return fmt.Errorf("HOLD: managed gateway did not pass runtime readiness before dependent appliances: %w", err)
		}
	}
	dnsPlan, err := dns.PlanFromSite(s)
	if err != nil {
		return fmt.Errorf("resolve DNS readiness contract: %w", err)
	}
	for _, module := range deploymentModuleNames(s) {
		if !modules.IsEnabled(s, module) && module != "portal" {
			continue
		}
		if err := proxmox.ProvisionModule(context.Background(), proxmoxClient, proxmoxPlan, module); err != nil {
			return fmt.Errorf("deploy %s appliances: %w", module, err)
		}
		for _, guest := range proxmoxPlan.Guests {
			matches := guest.Owner == "boetticher/module/"+module
			if module == "portal" {
				matches = guest.Name == "lab-portal-01"
			}
			if !matches || guest.Kind != proxmox.KindLXC {
				continue
			}
			guestRunner := applianceSSHRunner(s, *siteDir, guest.Name)
			if err := proxmox.WaitForSSH(context.Background(), guestRunner, guest.Address, "root", 30, 2*time.Second); err != nil {
				return fmt.Errorf("HOLD: %s guest %s is not reachable after first boot: %w", module, guest.Name, err)
			}
			if err := installCredentialsForGuest(context.Background(), guestRunner, guest.Name, credentialBindings, secretValues); err != nil {
				return fmt.Errorf("install %s credentials: %w", guest.Name, err)
			}
			if module == "dns" {
				if err := ansible.RunLimited(context.Background(), ansiblePlaybook, inventoryPath, variables, guest.Name); err != nil {
					return fmt.Errorf("HOLD: configure DNS guest %s before dependent appliances: %w", guest.Name, err)
				}
				if guest.Name == "lab-dns-01" && s.Gateway.Mode == model.GatewayModeManaged {
					if err := installPowerDNSTSIG(context.Background(), guestRunner, guest.Address, dnsPlan, secretValues["firewall-ddns-tsig"]); err != nil {
						return fmt.Errorf("install PowerDNS TSIG state on %s: %w", guest.Name, err)
					}
				}
				if err := verifyDNSReadiness(context.Background(), guestRunner, guest.Address, dnsPlan.RecursiveProvider); err != nil {
					return fmt.Errorf("HOLD: DNS guest %s did not pass runtime readiness before dependent appliances: %w", guest.Name, err)
				}
			}
		}
	}
	if err := ansible.Run(context.Background(), ansiblePlaybook, inventoryPath, variables); err != nil {
		return err
	}
	loggingClientCertificates, loggingCollectorCertificate, err := signLoggingCertificates(authority, s, csrDir)
	if err != nil {
		return fmt.Errorf("sign logging transport certificates: %w", err)
	}
	if err := installModuleRuntimeConfigs(context.Background(), *siteDir, s, proxmoxPlan); err != nil {
		return err
	}
	portalCSR, err := os.ReadFile(filepath.Join(csrDir, "portal.csr.pem"))
	if err != nil {
		return fmt.Errorf("read endpoint-generated portal CSR: %w", err)
	}
	var monitorCertificate pki.ServerCertificate
	var litellmCertificate pki.ServerCertificate
	var streamDeckCertificate pki.ClientCertificate
	var octoprintCertificate pki.ServerCertificate
	var aiopsCertificates map[string]string
	if monitoringEnabled {
		monitorCSR, readErr := os.ReadFile(filepath.Join(csrDir, "monitor.csr.pem"))
		if readErr != nil {
			return fmt.Errorf("read endpoint-generated monitor CSR: %w", readErr)
		}
		monitorCertificate, err = pki.SignServerCSR(authority, string(monitorCSR), "monitor", s.Network.Domain, []string{"lab-monitor-01." + s.Network.Domain}, time.Now().UTC())
		if err != nil {
			return fmt.Errorf("sign monitor endpoint CSR: %w", err)
		}
	}
	if modules.IsEnabled(s, "litellm") {
		litellmCSR, readErr := os.ReadFile(filepath.Join(csrDir, "litellm.csr.pem"))
		if readErr != nil {
			return fmt.Errorf("read endpoint-generated LiteLLM CSR: %w", readErr)
		}
		litellmCertificate, err = pki.SignServerCSR(authority, string(litellmCSR), "litellm", s.Network.Domain, []string{"ai." + s.Network.Domain, "lab-litellm-01." + s.Network.Domain}, time.Now().UTC())
		if err != nil {
			return fmt.Errorf("sign LiteLLM endpoint CSR: %w", err)
		}
	}
	if modules.IsEnabled(s, "streamdeck") {
		streamDeckCSR, readErr := os.ReadFile(filepath.Join(csrDir, "streamdeck.csr.pem"))
		if readErr != nil {
			return fmt.Errorf("read endpoint-generated StreamDeck CSR: %w", readErr)
		}
		streamDeckCertificate, err = pki.SignClientCSR(authority, string(streamDeckCSR), "lab-streamdeck-01", s.Network.Domain, time.Now().UTC())
		if err != nil {
			return fmt.Errorf("sign StreamDeck client CSR: %w", err)
		}
	}
	if modules.IsEnabled(s, "printer") {
		octoprintCSR, readErr := os.ReadFile(filepath.Join(csrDir, "octoprint.csr.pem"))
		if readErr != nil {
			return fmt.Errorf("read endpoint-generated OctoPrint CSR: %w", readErr)
		}
		octoprintCertificate, err = pki.SignServerCSR(authority, string(octoprintCSR), "octoprint", s.Network.Domain, []string{"printer." + s.Network.Domain, "lab-printer-01." + s.Network.Domain}, time.Now().UTC())
		if err != nil {
			return fmt.Errorf("sign OctoPrint endpoint CSR: %w", err)
		}
	}
	if modules.IsEnabled(s, "aiops") {
		aiopsCertificates, err = signAIOpsCertificates(authority, s, csrDir)
		if err != nil {
			return fmt.Errorf("sign AIOps endpoint certificates: %w", err)
		}
	}
	portalCertificate, err := pki.SignServerCSR(authority, string(portalCSR), "portal", s.Network.Domain, []string{"lab-portal-01." + s.Network.Domain}, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("sign portal endpoint CSR: %w", err)
	}
	runtimeVariables["pki_bootstrap_phase"] = false
	if monitoringEnabled {
		runtimeVariables["monitor_server_cert_pem"] = monitorCertificate.ChainPEM
	}
	if modules.IsEnabled(s, "litellm") {
		runtimeVariables["litellm_server_cert_pem"] = litellmCertificate.ChainPEM
	}
	if modules.IsEnabled(s, "streamdeck") {
		runtimeVariables["streamdeck_client_cert_pem"] = streamDeckCertificate.ChainPEM
	}
	if modules.IsEnabled(s, "printer") {
		runtimeVariables["octoprint_server_cert_pem"] = octoprintCertificate.ChainPEM
	}
	for name, certificate := range aiopsCertificates {
		runtimeVariables[name] = certificate
	}
	runtimeVariables["portal_server_cert_pem"] = portalCertificate.ChainPEM
	runtimeVariables["logging_client_certificates"] = loggingClientCertificates
	runtimeVariables["logging_collector_certificate"] = loggingCollectorCertificate
	variables, err = json.MarshalIndent(runtimeVariables, "", "  ")
	if err != nil {
		return err
	}
	variables = append(variables, '\n')
	if err := ansible.Run(context.Background(), ansiblePlaybook, inventoryPath, variables); err != nil {
		return fmt.Errorf("install endpoint-signed certificates: %w", err)
	}
	var pulseForward *proxmox.SSHLocalForward
	defer func() {
		if pulseForward != nil {
			_ = pulseForward.Close()
		}
	}()
	if monitoringEnabled {
		pulseRunner := proxmox.SSHRunner{
			IdentityFile:  operatorIdentityFile(s),
			ConfigFile:    filepath.Join(*siteDir, "generated", "ssh", "boetticher.conf"),
			StrictHostKey: "accept-new",
			HostAlias:     "lab-bastion",
		}
		pulseForward, err = pulseRunner.StartLocalForward(context.Background(), s.BootstrapAddress, "lab-jump", "10.10.10.20", 443)
		if err != nil {
			return fmt.Errorf("open Pulse API tunnel through Proxmox bastion: %w", err)
		}
		pulseBaseURL := "https://" + pulseForward.Address()
		clientCertificate, issueErr := pki.IssueClient(authority, "boetticher-reconciler", s.Network.Domain, time.Now().UTC())
		if issueErr != nil {
			return fmt.Errorf("issue runtime Pulse reconciliation certificate: %w", issueErr)
		}
		pulseAdmin, clientErr := pulse.NewAdminClient(pulse.ClientConfig{
			BaseURL: pulseBaseURL, AdminUser: "admin", AdminPassword: pulseAdminPassword,
			CAPEM: authority.IssuingCertPEM, ClientCertPEM: clientCertificate.CertPEM, ClientKeyPEM: clientCertificate.KeyPEM,
			ServerName: "monitor." + s.Network.Domain,
		})
		if clientErr != nil {
			return clientErr
		}
		if aiopsEnabled {
			if err := qualifyAndConfigureAIOps(context.Background(), *siteDir, *ageIdentity, s, authority, clientCertificate, pulseAdmin, runtimeVariables, ansiblePlaybook, inventoryPath); err != nil {
				return fmt.Errorf("HOLD: AIOps qualification failed: %w", err)
			}
		}
		if err := pulseAdmin.ConfigureProxmox(context.Background(), pulse.PVEConfig{
			Name: model.LogicalProxmoxIdentity, Host: "https://proxmox:8006",
			PreviousHost: "https://proxmox." + s.Network.Domain + ":8006",
			TokenID:      proxmox.PulseMonitoringUser + "!" + proxmox.PulseMonitoringToken, TokenSecret: pulseProxmoxToken,
			VerifySSL: true, MonitorVMs: true, MonitorContainers: true, MonitorStorage: true, MonitorBackups: true,
			MonitorPhysicalDisks: false, MonitorTemperatures: false,
		}); err != nil {
			return err
		}
		readToken, tokenErr := site.LoadPlatformSecret(*siteDir, s, *ageIdentity, "pulse_api_token")
		if errors.Is(tokenErr, site.ErrPlatformSecretMissing) {
			readToken, tokenErr = pulseAdmin.CreateReadToken(context.Background(), "boetticher monitoring read")
			if tokenErr != nil {
				return tokenErr
			}
			if err := site.StorePlatformSecret(*siteDir, s, *ageIdentity, "pulse_api_token", readToken); err != nil {
				return fmt.Errorf("store encrypted Pulse read token: %w", err)
			}
		} else if tokenErr != nil {
			return fmt.Errorf("load encrypted Pulse read token: %w", tokenErr)
		}
		pulseRead, clientErr := pulse.NewReadClient(pulse.ClientConfig{
			BaseURL: pulseBaseURL, APIToken: readToken,
			CAPEM: authority.IssuingCertPEM, ClientCertPEM: clientCertificate.CertPEM, ClientKeyPEM: clientCertificate.KeyPEM,
			ServerName: "monitor." + s.Network.Domain,
		})
		if clientErr != nil {
			return clientErr
		}
		readTokenRefreshed := false
		refreshPulseReadToken := func() error {
			if readTokenRefreshed {
				return errors.New("Pulse read token was already refreshed during this deployment")
			}
			readToken, tokenErr = pulseAdmin.CreateReadToken(context.Background(), "boetticher monitoring read")
			if tokenErr != nil {
				return tokenErr
			}
			if err := site.StorePlatformSecret(*siteDir, s, *ageIdentity, "pulse_api_token", readToken); err != nil {
				return fmt.Errorf("store encrypted Pulse read token: %w", err)
			}
			pulseRead, clientErr = pulse.NewReadClient(pulse.ClientConfig{
				BaseURL: pulseBaseURL, APIToken: readToken,
				CAPEM: authority.IssuingCertPEM, ClientCertPEM: clientCertificate.CertPEM, ClientKeyPEM: clientCertificate.KeyPEM,
				ServerName: "monitor." + s.Network.Domain,
			})
			if clientErr != nil {
				return clientErr
			}
			readTokenRefreshed = true
			return nil
		}
		health, err := pulseRead.Health(context.Background())
		if err != nil || !strings.EqualFold(health.Status, "healthy") {
			if err != nil {
				return fmt.Errorf("verify Pulse health: %w", err)
			}
			return fmt.Errorf("verify Pulse health: unexpected status %q", health.Status)
		}
		if _, err := pulseRead.StateSummary(context.Background()); err != nil {
			if !pulse.IsUnauthorized(err) {
				return fmt.Errorf("verify Pulse state summary: %w", err)
			}
			if refreshErr := refreshPulseReadToken(); refreshErr != nil {
				return fmt.Errorf("refresh Pulse read token after unauthorized response: %w", refreshErr)
			}
			if _, retryErr := pulseRead.StateSummary(context.Background()); retryErr != nil {
				return fmt.Errorf("verify Pulse state summary after read-token refresh: %w", retryErr)
			}
		}
		if _, err := pulseRead.Resources(context.Background()); err != nil {
			if !pulse.IsUnauthorized(err) || readTokenRefreshed {
				return fmt.Errorf("verify Pulse resources: %w", err)
			}
			if refreshErr := refreshPulseReadToken(); refreshErr != nil {
				return fmt.Errorf("refresh Pulse read token after unauthorized response: %w", refreshErr)
			}
			if _, retryErr := pulseRead.Resources(context.Background()); retryErr != nil {
				return fmt.Errorf("verify Pulse resources after read-token refresh: %w", retryErr)
			}
		}

		agentBindings, bindingErr := monitoringAgentCredentialBindings(s)
		if bindingErr != nil {
			return bindingErr
		}
		if len(agentBindings) > 0 {
			agentToken, agentTokenErr := site.LoadPlatformSecret(*siteDir, s, *ageIdentity, "pulse_agent_token")
			if errors.Is(agentTokenErr, site.ErrPlatformSecretMissing) {
				agentToken, agentTokenErr = pulseAdmin.CreateAgentReportToken(context.Background(), "boetticher monitoring agent")
				if agentTokenErr != nil {
					return agentTokenErr
				}
				if err := site.StorePlatformSecret(*siteDir, s, *ageIdentity, "pulse_agent_token", agentToken); err != nil {
					return fmt.Errorf("store encrypted Pulse agent token: %w", err)
				}
			} else if agentTokenErr != nil {
				return fmt.Errorf("load encrypted Pulse agent token: %w", agentTokenErr)
			}

			for _, target := range ansible.MonitoringAgentTargets(s) {
				var agentRunner proxmox.CommandRunner
				if target == model.LogicalProxmoxIdentity {
					agentRunner = proxmox.SSHRunner{
						IdentityFile:  operatorIdentityFile(s),
						ConfigFile:    filepath.Join(*siteDir, "generated", "ssh", "boetticher.conf"),
						StrictHostKey: "accept-new", HostKeyAlias: model.LogicalProxmoxIdentity,
					}
				} else {
					agentRunner = applianceSSHRunner(s, *siteDir, target)
				}
				if err := installCredentialsForGuest(context.Background(), agentRunner, target, agentBindings, map[string]string{"pulse_agent_token": agentToken}); err != nil {
					return fmt.Errorf("install Pulse agent credential on %s: %w", target, err)
				}
			}
			agentDropIns, dropInErr := credentialDropIns(agentBindings)
			if dropInErr != nil {
				return dropInErr
			}
			existingDropIns, ok := runtimeVariables["credential_dropins"].(map[string]map[string]string)
			if !ok {
				existingDropIns = map[string]map[string]string{}
			}
			for guest, dropIns := range agentDropIns {
				if existingDropIns[guest] == nil {
					existingDropIns[guest] = map[string]string{}
				}
				for unit, content := range dropIns {
					existingDropIns[guest][unit] = content
				}
			}
			runtimeVariables["credential_dropins"] = existingDropIns
			runtimeVariables["pulse_agent_install_enabled"] = true
			agentVariables, marshalErr := json.MarshalIndent(runtimeVariables, "", "  ")
			if marshalErr != nil {
				return marshalErr
			}
			agentVariables = append(agentVariables, '\n')
			for _, target := range ansible.MonitoringAgentTargets(s) {
				if err := ansible.RunLimited(context.Background(), ansiblePlaybook, inventoryPath, agentVariables, target); err != nil {
					return fmt.Errorf("install Pulse agent on %s: %w", target, err)
				}
			}
		}
		if modules.IsEnabled(s, "streamdeck") {
			streamDeckToken, tokenErr := site.LoadPlatformSecret(*siteDir, s, *ageIdentity, "streamdeck_pulse_token")
			if errors.Is(tokenErr, site.ErrPlatformSecretMissing) {
				streamDeckToken, tokenErr = pulseAdmin.CreateReadToken(context.Background(), "boetticher streamdeck monitoring read")
				if tokenErr == nil {
					tokenErr = site.StorePlatformSecret(*siteDir, s, *ageIdentity, "streamdeck_pulse_token", streamDeckToken)
				}
			}
			if tokenErr != nil {
				return fmt.Errorf("prepare encrypted StreamDeck Pulse token: %w", tokenErr)
			}
			bindings, bindingErr := streamDeckCredentialBindings(s)
			if bindingErr != nil {
				return bindingErr
			}
			if err := installCredentialsForGuest(context.Background(), applianceSSHRunner(s, *siteDir, "lab-streamdeck-01"), "lab-streamdeck-01", bindings, map[string]string{"streamdeck_pulse_token": streamDeckToken}); err != nil {
				return fmt.Errorf("install StreamDeck Pulse credential: %w", err)
			}
			dropins, dropErr := credentialDropIns(bindings)
			if dropErr != nil {
				return dropErr
			}
			existing, _ := runtimeVariables["credential_dropins"].(map[string]map[string]string)
			if existing == nil {
				existing = map[string]map[string]string{}
			}
			for guest, units := range dropins {
				if existing[guest] == nil {
					existing[guest] = map[string]string{}
				}
				for unit, content := range units {
					existing[guest][unit] = content
				}
			}
			runtimeVariables["credential_dropins"] = existing
			runtimeVariables["streamdeck_token_install_enabled"] = true
			streamDeckVariables, marshalErr := json.MarshalIndent(runtimeVariables, "", "  ")
			if marshalErr != nil {
				return marshalErr
			}
			streamDeckVariables = append(streamDeckVariables, '\n')
			if err := ansible.RunLimited(context.Background(), ansiblePlaybook, inventoryPath, streamDeckVariables, "lab-streamdeck-01"); err != nil {
				return fmt.Errorf("start StreamDeck status service: %w", err)
			}
		}
	}
	if pulseForward != nil {
		if err := pulseForward.Close(); err != nil {
			return fmt.Errorf("close Pulse API tunnel: %w", err)
		}
		pulseForward = nil
	}
	if err := proxmoxClient.ApplyBackupJob(context.Background(), node, proxmox.BackupJob{
		JobName: backupPlan.JobName, ModelRevision: backupPlan.ModelRevision, StorageTarget: backupPlan.StorageTarget,
		Schedule: backupPlan.Schedule, VMIDList: backupPlan.VMIDList(), Retention: backupPlan.Retention,
	}); err != nil {
		return err
	}
	if err := revokeTemporaryRootAccess(context.Background(), s, *siteDir, proxmoxPlan, operatorPublicKey); err != nil {
		return fmt.Errorf("HOLD: deployment converged but temporary root access cleanup failed: %w", err)
	}
	if len(s.PendingDNSDeletions) > 0 {
		if err := site.SavePendingDNSDeletions(*siteDir, s, nil); err != nil {
			return fmt.Errorf("clear reconciled DNS deletion state: %w", err)
		}
		s.PendingDNSDeletions = nil
	}
	if err := writeModelProjections(*siteDir, s); err != nil {
		return err
	}
	if err := rebuildPortal(*siteDir, s); err != nil {
		return err
	}
	fmt.Fprintf(out, "Deployment: PASS mode=%s model=%s (storage %s)\n", s.Gateway.Mode, firewallPlan.ModelRevision, storagePlan.GuestStorage)
	return nil
}

func absolutePortalSourceDir(siteDir string) (string, error) {
	absoluteSiteDir, err := filepath.Abs(siteDir)
	if err != nil {
		return "", fmt.Errorf("resolve portal source directory: %w", err)
	}
	return filepath.Join(absoluteSiteDir, "generated", "portal"), nil
}

func artifactQualificationStatus(artifact model.Artifact) string {
	if artifact.Name == "" {
		return "no appliance artifact"
	}
	if artifact.ContentSHA256 == "" {
		return "NOT BUILT (qualified content evidence absent)"
	}
	return "QUALIFIED content=" + artifact.ContentSHA256
}

// deploymentModuleNames returns the resolved module graph order carried by
// Site. The managed firewall is handled immediately above because dependent
// guests must not be created until its management leg and forwarding policy
// are ready. The Core portal follows active modules because it consumes the
// generated platform model but does not provide a module capability.
func deploymentModuleNames(s model.Site) []string {
	result := make([]string, 0, len(s.Modules)+1)
	for _, module := range s.Modules {
		if module.Enabled && module.Name != "firewall" {
			result = append(result, module.Name)
		}
	}
	result = append(result, "portal")
	return result
}

func loadBootstrapOperatorKey(siteDir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(siteDir, "generated", "bootstrap.json"))
	if err != nil {
		return "", fmt.Errorf("read bootstrap operator key evidence: %w", err)
	}
	var evidence struct {
		OperatorPublicKey string `json:"operator_public_key"`
	}
	if err := json.Unmarshal(data, &evidence); err != nil {
		return "", fmt.Errorf("decode bootstrap operator key evidence: %w", err)
	}
	if evidence.OperatorPublicKey == "" {
		return "", errors.New("HOLD: bootstrap operator public key evidence is absent; rerun bootstrap")
	}
	return evidence.OperatorPublicKey, nil
}

func verifyGatewayReadiness(ctx context.Context, runner proxmox.CommandRunner, address string) error {
	if runner == nil {
		return errors.New("gateway readiness runner is required")
	}
	command := "set -eu; nft -c -f /etc/nftables.conf; systemctl is-active nftables kea-dhcp4-server kea-dhcp-ddns-server dnsmasq chrony; test \"$(sysctl -n net.ipv4.ip_forward)\" = 1"
	if _, err := runner.Run(ctx, address, "root", command); err != nil {
		return fmt.Errorf("gateway policy, DHCP, NTP, and forwarding checks failed: %w", err)
	}
	return nil
}

func verifyFirewallBootstrapNetwork(ctx context.Context, runner proxmox.CommandRunner) error {
	if runner == nil {
		return errors.New("firewall bootstrap network runner is required")
	}
	command := "set -eu; for interface in wan0 trusted0 servers0 sandbox0 mgmt0 transit0 infra0; do ip link show dev \"$interface\" >/dev/null; done; ip -4 -o addr show dev trusted0 | grep -Fq '10.10.30.1/24'; ip -4 -o addr show dev servers0 | grep -Fq '10.10.20.1/24'; ip -4 -o addr show dev sandbox0 | grep -Fq '10.10.40.1/24'; ip -4 -o addr show dev mgmt0 | grep -Fq '10.10.99.1/24'; ip -4 -o addr show dev transit0 | grep -Fq '10.10.5.1/24'; ip -4 -o addr show dev infra0 | grep -Fq '10.10.10.1/24'"
	if _, err := runner.Run(ctx, "10.10.99.1", "root", command); err != nil {
		return fmt.Errorf("role-named interfaces or static addresses are not ready: %w", err)
	}
	return nil
}

func verifyDNSReadiness(ctx context.Context, runner proxmox.CommandRunner, address, provider string) error {
	if runner == nil {
		return errors.New("DNS readiness runner is required")
	}
	service := "blocky"
	config := "/etc/blocky/config.yml"
	checks := ""
	if provider == string(model.DNSProviderAdGuard) {
		service = "adguardhome"
		config = "/opt/AdGuardHome/AdGuardHome.yaml"
	} else if provider == string(model.DNSProviderBlocky) {
		checks = "; test ! -e /opt/AdGuardHome/AdGuardHome; blocky version | grep -Fq '0.34.0'; blocky validate --config /etc/blocky/config.yml"
	}
	command := fmt.Sprintf("set -eu; systemctl is-active pdns chrony %s; test -s /etc/powerdns/pdns.conf; test -s %s%s", service, config, checks)
	if _, err := runner.Run(ctx, address, "root", command); err != nil {
		return fmt.Errorf("authoritative, NTP, and %s resolver checks failed: %w", provider, err)
	}
	return nil
}

func signLoggingCertificates(authority pki.Authority, s model.Site, csrDir string) (map[string]string, string, error) {
	clients := map[string]string{}
	for _, component := range s.PlatformComponents() {
		if !component.Logging || component.Name == "lab-log-01" {
			continue
		}
		csr, err := os.ReadFile(filepath.Join(csrDir, "logging-"+component.Name+".csr.pem"))
		if err != nil {
			return nil, "", fmt.Errorf("read %s logging CSR: %w", component.Name, err)
		}
		certificate, err := pki.SignClientCSR(authority, string(csr), component.Name, s.Network.Domain, time.Now().UTC())
		if err != nil {
			return nil, "", fmt.Errorf("sign %s logging CSR: %w", component.Name, err)
		}
		clients[component.Name] = certificate.ChainPEM
	}
	collectorCSR, err := os.ReadFile(filepath.Join(csrDir, "logging-collector.csr.pem"))
	if err != nil {
		return nil, "", fmt.Errorf("read logging collector CSR: %w", err)
	}
	collector, err := pki.SignServerCSR(authority, string(collectorCSR), "logs", s.Network.Domain, []string{"lab-log-01." + s.Network.Domain}, time.Now().UTC())
	if err != nil {
		return nil, "", fmt.Errorf("sign logging collector CSR: %w", err)
	}
	return clients, collector.ChainPEM, nil
}

func signAIOpsCertificates(authority pki.Authority, s model.Site, csrDir string) (map[string]string, error) {
	now := time.Now().UTC()
	readCSR := func(name string) (string, error) {
		data, err := os.ReadFile(filepath.Join(csrDir, name+".csr.pem"))
		if err != nil {
			return "", fmt.Errorf("read %s CSR: %w", name, err)
		}
		return string(data), nil
	}
	serverRequests := []struct {
		file, identity, variable string
		aliases                  []string
	}{
		{"aiops", "aiops", "aiops_server_cert_pem", []string{"lab-aiops-01." + s.Network.Domain}},
		{"log-query", "log-query", "log_query_server_cert_pem", []string{"logs." + s.Network.Domain, "lab-log-01." + s.Network.Domain}},
	}
	result := make(map[string]string, 6)
	for _, request := range serverRequests {
		csr, err := readCSR(request.file)
		if err != nil {
			return nil, err
		}
		certificate, err := pki.SignServerCSR(authority, csr, request.identity, s.Network.Domain, request.aliases, now)
		if err != nil {
			return nil, fmt.Errorf("sign %s CSR: %w", request.file, err)
		}
		result[request.variable] = certificate.ChainPEM
	}
	clientRequests := []struct{ file, identity, variable string }{
		{"pulse-read", "aiops-pulse-read", "aiops_pulse_read_cert_pem"},
		{"pulse-note", "aiops-pulse-note", "aiops_pulse_note_cert_pem"},
		{"log-query-client", "aiops-log-read", "aiops_log_read_cert_pem"},
		{"ai-router-client", "aiops-router-client", "aiops_router_client_cert_pem"},
	}
	for _, request := range clientRequests {
		csr, err := readCSR(request.file)
		if err != nil {
			return nil, err
		}
		certificate, err := pki.SignServiceClientCSR(authority, csr, request.identity, now)
		if err != nil {
			return nil, fmt.Errorf("sign %s CSR: %w", request.file, err)
		}
		result[request.variable] = certificate.ChainPEM
	}
	return result, nil
}

func qualifyAndConfigureAIOps(ctx context.Context, siteDir, ageIdentity string, s model.Site, authority pki.Authority, controllerCertificate pki.ClientCertificate, pulseAdmin *pulse.Client, runtimeVariables map[string]any, ansiblePlaybook, inventoryPath string) error {
	modelConfig, err := selectedAIOpsModel(s)
	if err != nil {
		return err
	}
	runner := applianceSSHRunner(s, siteDir, "lab-litellm-01")
	metadata, err := runner.RunArgs(ctx, "10.10.20.60", "root", []string{"/usr/local/libexec/boetticher-litellm-model-capabilities", modelConfig.Model})
	if err != nil {
		return fmt.Errorf("read pinned LiteLLM model metadata: %w", err)
	}
	if _, err := aiopsmodel.DecodeModelCapabilities(metadata); err != nil {
		return err
	}
	routerClient, err := controllerMTLSClient(authority, controllerCertificate)
	if err != nil {
		return err
	}
	canaryContext, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if err := aiopsmodel.QualifyModelAlias(canaryContext, routerClient, "https://ai."+s.Network.Domain+"/v1/chat/completions", s.ModuleConfig["aiops"].ModelAlias); err != nil {
		return err
	}

	webhookSecret, err := loadOrCreateAIOpsSecret(siteDir, ageIdentity, s, "aiops_webhook_secret")
	if err != nil {
		return err
	}
	readToken, err := loadOrCreatePulseToken(siteDir, ageIdentity, s, "aiops_pulse_read_token", func() (string, error) {
		return pulseAdmin.CreateReadToken(ctx, "boetticher aiops read")
	})
	if err != nil {
		return err
	}
	noteToken, err := loadOrCreatePulseToken(siteDir, ageIdentity, s, "aiops_pulse_note_token", func() (string, error) {
		return pulseAdmin.CreateIncidentNoteToken(ctx, "boetticher aiops notes")
	})
	if err != nil {
		return err
	}
	if err := pulseAdmin.ConfigureAIOpsWebhook(ctx, "https://aiops."+s.Network.Domain+"/v1/pulse/events", webhookSecret, "10.10.20.90/32"); err != nil {
		return err
	}

	allBindings, err := deploymentCredentialBindings(s)
	if err != nil {
		return err
	}
	var bindings []deploymentCredential
	for _, binding := range allBindings {
		if binding.Guest == "lab-aiops-01" {
			bindings = append(bindings, binding)
		}
	}
	values := map[string]string{"aiops_webhook_secret": webhookSecret, "aiops_pulse_read_token": readToken, "aiops_pulse_note_token": noteToken}
	aiopsRunner := applianceSSHRunner(s, siteDir, "lab-aiops-01")
	if err := installCredentialsForGuest(ctx, aiopsRunner, "lab-aiops-01", bindings, values); err != nil {
		return err
	}
	dropIns, err := credentialDropIns(bindings)
	if err != nil {
		return err
	}
	existing, _ := runtimeVariables["credential_dropins"].(map[string]map[string]string)
	if existing == nil {
		existing = map[string]map[string]string{}
	}
	existing["lab-aiops-01"] = dropIns["lab-aiops-01"]
	runtimeVariables["credential_dropins"] = existing
	runtimeVariables["aiops_runtime_credentials_ready"] = true
	runtimeVariables["aiops_model_alias_qualified"] = true
	variables, err := json.MarshalIndent(runtimeVariables, "", "  ")
	if err != nil {
		return err
	}
	return ansible.RunLimited(ctx, ansiblePlaybook, inventoryPath, append(variables, '\n'), "lab-aiops-01")
}

func selectedAIOpsModel(s model.Site) (model.LiteLLMModelConfig, error) {
	alias := s.ModuleConfig["aiops"].ModelAlias
	var selected model.LiteLLMModelConfig
	for _, candidate := range s.ModuleConfig["litellm"].Models {
		if candidate.Alias != alias {
			continue
		}
		if selected.Alias != "" {
			return model.LiteLLMModelConfig{}, errors.New("AIOps model alias is ambiguous")
		}
		selected = candidate
	}
	if selected.Alias == "" {
		return model.LiteLLMModelConfig{}, errors.New("AIOps model alias is undeclared")
	}
	return selected, nil
}

func controllerMTLSClient(authority pki.Authority, certificate pki.ClientCertificate) (*http.Client, error) {
	identity, err := tls.X509KeyPair([]byte(certificate.CertPEM), []byte(certificate.KeyPEM))
	if err != nil {
		return nil, fmt.Errorf("load controller AIOps canary identity: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(authority.RootCertPEM + authority.IssuingCertPEM)) {
		return nil, errors.New("platform CA contains no certificates")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{identity}}, DisableCompression: true, ResponseHeaderTimeout: 30 * time.Second}
	return &http.Client{Transport: transport, Timeout: 60 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("AI Router redirects are forbidden") }}, nil
}

func loadOrCreateAIOpsSecret(siteDir, ageIdentity string, s model.Site, key string) (string, error) {
	value, err := site.LoadPlatformSecret(siteDir, s, ageIdentity, key)
	if err == nil {
		return value, nil
	}
	if !errors.Is(err, site.ErrPlatformSecretMissing) {
		return "", fmt.Errorf("load encrypted %s: %w", key, err)
	}
	var data [32]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", fmt.Errorf("generate %s: %w", key, err)
	}
	value = base64.RawURLEncoding.EncodeToString(data[:])
	if err := site.StorePlatformSecret(siteDir, s, ageIdentity, key, value); err != nil {
		return "", fmt.Errorf("store encrypted %s: %w", key, err)
	}
	return value, nil
}

func loadOrCreatePulseToken(siteDir, ageIdentity string, s model.Site, key string, create func() (string, error)) (string, error) {
	value, err := site.LoadPlatformSecret(siteDir, s, ageIdentity, key)
	if err == nil {
		return value, nil
	}
	if !errors.Is(err, site.ErrPlatformSecretMissing) {
		return "", fmt.Errorf("load encrypted %s: %w", key, err)
	}
	value, err = create()
	if err != nil {
		return "", err
	}
	if err := site.StorePlatformSecret(siteDir, s, ageIdentity, key, value); err != nil {
		return "", fmt.Errorf("store encrypted %s: %w", key, err)
	}
	return value, nil
}

// installModuleRuntimeConfigs is the deployment boundary for the common
// non-secret appliance contract. Module declarations remain the source of
// guest identity and runtime configuration; the SSH runner is only the Core
// transport used to install the already-validated document.
func installModuleRuntimeConfigs(ctx context.Context, siteDir string, s model.Site, plan proxmox.Plan) error {
	declarations := make(map[string]model.ModuleDeclaration, len(s.Declarations))
	for _, declaration := range s.Declarations {
		declarations[declaration.Module] = declaration
	}
	resolvedGuests := make(map[string]proxmox.GuestPlan, len(plan.Guests))
	for _, guest := range plan.Guests {
		if guest.Owner != "" {
			resolvedGuests[guest.Name] = guest
		}
	}
	for _, guest := range s.PlatformComponents() {
		if guest.Module == "" && guest.Name != "lab-portal-01" {
			continue
		}
		resolvedGuest, ok := resolvedGuests[guest.Name]
		if !ok || resolvedGuest.Artifact.ContentSHA256 == "" {
			return fmt.Errorf("runtime artifact identity for %s: qualified artifact content checksum is missing", guest.Name)
		}
		if guest.Module == "" {
			runner := applianceSSHRunner(s, siteDir, guest.Name)
			if err := appliance.InstallArtifactIdentity(ctx, runner, guest.Address, "root", resolvedGuest.Artifact); err != nil {
				return fmt.Errorf("install artifact identity for %s: %w", guest.Name, err)
			}
			continue
		}
		declaration, ok := declarations[guest.Module]
		if !ok {
			return fmt.Errorf("runtime configuration for %s: module declaration is missing", guest.Name)
		}
		resolvedDeclaration, resolveErr := resolvedDeclarationForGuest(declaration, resolvedGuest)
		if resolveErr != nil {
			return fmt.Errorf("runtime configuration for %s: %w", guest.Name, resolveErr)
		}
		config, err := appliance.RenderRuntimeConfig(s, guest, resolvedDeclaration)
		if err != nil {
			return fmt.Errorf("render runtime configuration for %s: %w", guest.Name, err)
		}
		runner := applianceSSHRunner(s, siteDir, guest.Name)
		if err := appliance.InstallRuntimeConfig(ctx, runner, guest.Address, "root", config); err != nil {
			return fmt.Errorf("install runtime configuration for %s: %w", guest.Name, err)
		}
		if err := appliance.InstallArtifactIdentity(ctx, runner, guest.Address, "root", resolvedDeclaration.Artifact); err != nil {
			return fmt.Errorf("install artifact identity for %s: %w", guest.Name, err)
		}
	}
	return nil
}

// applianceSSHRunner selects the generated host alias so internal appliance
// connections use the same bastion/host-key policy as Ansible and operator
// SSH. Passing the guest address as the SSH target would bypass ProxyJump
// because the generated configuration is keyed by stable appliance identity.
func applianceSSHRunner(s model.Site, siteDir, hostAlias string) proxmox.SSHRunner {
	return proxmox.SSHRunner{
		IdentityFile:  operatorIdentityFile(s),
		ConfigFile:    filepath.Join(siteDir, "generated", "ssh", "boetticher.conf"),
		StrictHostKey: "accept-new",
		HostAlias:     hostAlias,
	}
}

func revokeTemporaryRootAccess(ctx context.Context, s model.Site, siteDir string, plan proxmox.Plan, operatorPublicKey string) error {
	for _, guest := range plan.Guests {
		if guest.Owner == "" || guest.Address == "" {
			continue
		}
		runner := applianceSSHRunner(s, siteDir, guest.Name)
		if err := proxmox.RevokeTemporaryRootAccess(ctx, runner, guest.Address, "root", operatorPublicKey, false); err != nil {
			return fmt.Errorf("revoke root access on %s: %w", guest.Name, err)
		}
	}
	hostRunner := proxmoxRootSSHRunner(s, siteDir)
	if err := proxmox.RevokeTemporaryRootAccess(ctx, hostRunner, s.BootstrapAddress, "root", operatorPublicKey, true); err != nil {
		return fmt.Errorf("revoke root access on %s: %w", model.LogicalProxmoxIdentity, err)
	}
	return nil
}

func resolvedDeclarationForGuest(declaration model.ModuleDeclaration, guest proxmox.GuestPlan) (model.ModuleDeclaration, error) {
	if declaration.Module == "" || declaration.Module != strings.TrimPrefix(guest.Owner, "boetticher/module/") {
		return model.ModuleDeclaration{}, fmt.Errorf("module declaration ownership does not match guest %s", guest.Name)
	}
	if guest.Artifact.Name == "" || guest.Artifact.ContentSHA256 == "" || guest.Artifact.DefinitionSHA256 == "" {
		return model.ModuleDeclaration{}, fmt.Errorf("qualified artifact identity is incomplete")
	}
	declaration.Artifact = guest.Artifact
	return declaration, nil
}

func loadProxmoxClient(siteDir string, s model.Site, ageIdentity, caFile string, insecure bool) (*proxmox.Client, site.ProxmoxCredentials, error) {
	return loadProxmoxClientWithSnippetUser(siteDir, s, ageIdentity, caFile, insecure, model.DefaultAdminSSHUser)
}

func loadProxmoxClientWithSnippetUser(siteDir string, s model.Site, ageIdentity, caFile string, insecure bool, snippetUser string) (*proxmox.Client, site.ProxmoxCredentials, error) {
	if s.BootstrapAddress == "" {
		return nil, site.ProxmoxCredentials{}, errors.New("bootstrap endpoint is not configured")
	}
	credentials, err := site.LoadProxmoxCredentials(siteDir, s, ageIdentity)
	if err != nil {
		return nil, site.ProxmoxCredentials{}, fmt.Errorf("load encrypted Proxmox API credentials: %w", err)
	}
	client, err := proxmox.NewClient(proxmox.Config{
		BaseURL: "https://" + s.BootstrapAddress + ":8006/api2/json", User: credentials.APIUser,
		TokenID: credentials.TokenID, TokenSecret: credentials.TokenSecret, CAFile: caFile, Insecure: insecure,
		SnippetRunner: proxmox.SSHRunner{
			IdentityFile:  operatorIdentityFile(s),
			ConfigFile:    filepath.Join(siteDir, "generated", "ssh", "boetticher.conf"),
			StrictHostKey: "accept-new", HostKeyAlias: model.LogicalProxmoxIdentity,
		},
		SnippetAddress: s.BootstrapAddress, SnippetUser: snippetUser,
	})
	if err != nil {
		return nil, site.ProxmoxCredentials{}, err
	}
	return client, credentials, nil
}

func proxmoxRootSSHRunner(s model.Site, siteDir string) proxmox.SSHRunner {
	return proxmox.SSHRunner{
		IdentityFile:  operatorIdentityFile(s),
		ConfigFile:    filepath.Join(siteDir, "generated", "ssh", "boetticher.conf"),
		StrictHostKey: "accept-new",
		HostAlias:     model.LogicalProxmoxIdentity,
	}
}

func operatorIdentityFile(s model.Site) string {
	if identity := model.ExpandUserPath(s.SSHIdentityFile); identity != "" {
		return identity
	}
	publicKey := defaultOperatorPublicKey()
	if !strings.HasSuffix(publicKey, ".pub") {
		return ""
	}
	identity := strings.TrimSuffix(publicKey, ".pub")
	if _, err := os.Stat(identity); err != nil {
		return ""
	}
	return identity
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
	return nil
}
