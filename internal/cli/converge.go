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
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	aiopsmodel "github.com/gofastercloud/boetticher/internal/aiops"
	"github.com/gofastercloud/boetticher/internal/ansible"
	"github.com/gofastercloud/boetticher/internal/appliance"
	"github.com/gofastercloud/boetticher/internal/artifacts"
	"github.com/gofastercloud/boetticher/internal/backup"
	"github.com/gofastercloud/boetticher/internal/dns"
	"github.com/gofastercloud/boetticher/internal/firewall"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
	"github.com/gofastercloud/boetticher/internal/pki"
	"github.com/gofastercloud/boetticher/internal/portal"
	"github.com/gofastercloud/boetticher/internal/proxmox"
	"github.com/gofastercloud/boetticher/internal/pulse"
	"github.com/gofastercloud/boetticher/internal/site"
	"github.com/gofastercloud/boetticher/internal/sshconfig"
	"github.com/gofastercloud/boetticher/internal/storage"
	"github.com/gofastercloud/boetticher/internal/telemetry"
)

func runDeploy(args []string, out io.Writer) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runDeployWithContext(ctx, args, out)
}

func runDeployWithContext(ctx context.Context, args []string, out io.Writer) error {
	report := newDeploymentReport(out)
	ctx = telemetry.WithObserver(ctx, report)
	var cleanup func(context.Context) error
	operationErr := runDeployOperation(ctx, args, out, report, func(fn func(context.Context) error) {
		cleanup = fn
	})
	if cleanup != nil {
		report.setCleanup(true, false, nil)
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		cleanupErr := report.timed("cleanup", "temporary-authority", "deployment", func() error {
			return cleanup(cleanupCtx)
		})
		cancel()
		if cleanupErr == nil {
			report.setCleanup(true, true, nil)
		} else {
			report.setCleanup(true, false, cleanupErr)
		}
		operationErr = combineDeploymentErrors(operationErr, cleanupErr)
	}
	operationErr = report.finalize(operationErr)
	return deploymentErrorForOperator(operationErr)
}

func runDeployOperation(ctx context.Context, args []string, out io.Writer, report *deploymentReport, registerCleanup deploymentCleanupRegistrar) (err error) {
	fs := flag.NewFlagSet("deploy", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	proxmoxCA := fs.String("proxmox-ca", "", "Proxmox API CA PEM file")
	insecure := fs.Bool("insecure", false, "explicitly allow self-signed Proxmox API TLS")
	dryRun := fs.Bool("dry-run", false, "render and validate policy without connecting")
	rotateAirVPN := fs.Bool("rotate-airvpn-profile", false, "explicitly regenerate and retain the AirVPN WireGuard profile")
	confirm := fs.Bool("confirm", false, "confirm destructive appliance replacement or purge actions")
	if err := fs.Parse(args); err != nil {
		return err
	}
	report.dryRun = *dryRun
	_ = confirm // replacement confirmation is enforced by the shared provider plan
	report.start("validate", "Validate desired state")
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	modelRevision, err := s.Revision()
	if err != nil {
		return fmt.Errorf("calculate model revision: %w", err)
	}
	report.setIdentity(model.PlatformVersion, modelRevision)
	report.setTimingPath(filepath.Join(site.RuntimeDir(s), "deploy", report.runID+".json"))
	var airvpnProfile *preparedAirVPNProfile
	if err := report.timed("validate", "provider", "airvpn-profile", func() error {
		var profileErr error
		airvpnProfile, profileErr = prepareAirVPNProfile(ctx, *siteDir, s, *ageIdentity, *dryRun, *rotateAirVPN)
		return profileErr
	}); err != nil {
		return err
	}
	var firewallPlan firewall.Plan
	if err := report.timed("validate", "local", "firewall-plan", func() error {
		if airvpnProfile == nil {
			firewallPlan, err = firewall.PlanFromSite(s)
		} else {
			firewallPlan, err = firewall.PlanFromSiteWithAirVPN(s, airvpnProfile.Metadata)
		}
		return err
	}); err != nil {
		return err
	}
	if airvpnProfile != nil && airvpnProfile.Created {
		report.recordMutation("Secrets", "airvpn_wireguard_config", "encrypted provider profile stored", true)
	}
	var airvpnMetadata *firewall.AirVPNProfile
	if airvpnProfile != nil {
		airvpnMetadata = &airvpnProfile.Metadata
	}
	report.complete()
	if *dryRun {
		report.start("artifacts", "Resolve qualified artifacts")
		fmt.Fprintf(out, "Deployment plan: PASS model %s\n", firewallPlan.ModelRevision)
		fmt.Fprintf(out, "  Mode: %s\n  Engine: %s\n  DHCP subnets: %d\n  Policy rules: %d\n", firewallPlan.Mode, firewallPlan.Engine, len(firewallPlan.DHCP), len(firewallPlan.Rules))
		if s.Gateway.Mode == model.GatewayModeManaged {
			ruleset, renderErr := renderDeploymentNFT(firewallPlan)
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
		fmt.Fprintln(out, "  Destructive actions: not applied (dry-run)")
		var plan proxmox.Plan
		if err := report.timed("artifacts", "local", "proxmox-plan", func() error {
			var planErr error
			plan, planErr = proxmox.PlanFromSite(s)
			return planErr
		}); err != nil {
			return err
		}
		if err := report.timed("artifacts", "qualification", "selected-artifacts", func() error {
			var qualifyErr error
			plan, qualifyErr = proxmox.ResolveQualifiedArtifacts(*siteDir, plan, true)
			return qualifyErr
		}); err != nil {
			fmt.Fprintf(out, "  Artifact qualification: FAIL (%s)\n", compactError(err))
			return err
		}
		fmt.Fprintln(out, "  Artifact qualification: PASS (all selected artifacts qualified)")
		if err := report.timed("artifacts", "local", "static-readiness", func() error {
			return validateStaticDeploymentReadiness(*siteDir, s, *ageIdentity, firewallPlan, plan)
		}); err != nil {
			fmt.Fprintf(out, "  Static deployment checks: FAIL (%s)\n", compactError(err))
			return fmt.Errorf("static preflight failed: %w", err)
		}
		fmt.Fprintln(out, "  Static deployment checks: PASS")
		fmt.Fprintln(out, "  Appliances:")
		for _, guest := range plan.Guests {
			fmt.Fprintf(out, "    %s  %s  %s  definition=%s\n", guest.Name, guest.Artifact.Name, artifactQualificationStatus(guest.Artifact), guest.Artifact.DefinitionSHA256)
			for _, volume := range guest.Volumes {
				fmt.Fprintf(out, "    volume %s -> %s (%s, backup=%t)\n", volume.Name, volume.MountPath, volume.Placement, volume.Backup)
			}
		}
		report.complete()
		return nil
	}
	report.start("artifacts", "Resolve qualified artifacts")
	ansibleRoot, err := applianceBuildSourceRoot()
	if err != nil {
		return fmt.Errorf("resolve Ansible playbook source: %w", err)
	}
	ansiblePlaybook := filepath.Join(ansibleRoot, "ansible", "site.yml")
	endpointLookup := net.LookupIP
	rootRunner := proxmoxRootSSHRunner(s, *siteDir)
	if s.Gateway.Mode == model.GatewayModeManaged {
		if err := proxmox.WaitForSSH(ctx, rootRunner, s.BootstrapAddress, "root", 1, 0); err != nil {
			return fmt.Errorf("HOLD: temporary root deployment authority is unavailable; rerun bootstrap or recovery: %w", err)
		}
		endpointLookup = endpointLookupWithFallback(net.LookupIP, remoteEndpointResolver(ctx, rootRunner, s.BootstrapAddress, "root"))
	}
	if airvpnMetadata != nil {
		if err := report.timed("artifacts", "provider", "airvpn-endpoint", func() error {
			var bindErr error
			firewallPlan, bindErr = firewall.BindAirVPNEndpoint(firewallPlan, endpointLookup)
			return bindErr
		}); err != nil {
			return err
		}
		// Carry the resolved, non-secret endpoint addresses into every later
		// variables/projection render. The profile pointer in the plan is the
		// runtime-only metadata authority for this deployment.
		airvpnMetadata = firewallPlan.AirVPN
	}
	backupPlan, err := backup.PlanFromSite(s)
	if err != nil {
		return err
	}
	storagePlan, err := storage.PlanFromSite(s)
	if err != nil {
		return err
	}
	var proxmoxPlan proxmox.Plan
	if err := report.timed("artifacts", "local", "proxmox-plan", func() error {
		var planErr error
		proxmoxPlan, planErr = proxmox.PlanFromSite(s)
		return planErr
	}); err != nil {
		return err
	}
	if err := report.timed("artifacts", "qualification", "selected-artifacts", func() error {
		var qualifyErr error
		proxmoxPlan, qualifyErr = proxmox.ResolveQualifiedArtifacts(*siteDir, proxmoxPlan, true)
		return qualifyErr
	}); err != nil {
		return err
	}
	report.complete()
	report.start("credentials-pki", "Prepare credentials and PKI")
	if err := report.timed("credentials-pki", "local", "static-readiness", func() error {
		return validateStaticDeploymentReadiness(*siteDir, s, *ageIdentity, firewallPlan, proxmoxPlan)
	}); err != nil {
		return fmt.Errorf("static preflight failed: %w", err)
	}
	retainedGuests, err := retainedGuestPlans(s)
	if err != nil {
		return err
	}
	operatorPublicKey, err := loadBootstrapOperatorKey(*siteDir)
	if err != nil {
		return err
	}
	var variables []byte
	if err := report.timed("credentials-pki", "local", "ansible-variables", func() error {
		if airvpnMetadata == nil {
			variables, err = ansible.VariablesWithOperatorKey(s, operatorPublicKey)
		} else {
			variables, err = ansible.VariablesWithOperatorKeyAndAirVPN(s, operatorPublicKey, *airvpnMetadata)
		}
		return err
	}); err != nil {
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
	portalContentDigest, err := portal.ContentDigest(portalSourceDir)
	if err != nil {
		return fmt.Errorf("digest generated portal: %w", err)
	}
	portalArchiveDir := filepath.Join(site.RuntimeDir(s), "portal")
	portalSourceArchive := filepath.Join(portalArchiveDir, portalContentDigest+".tar")
	if err := report.timed("credentials-pki", "local", "portal-archive", func() error {
		return portal.ContentArchive(portalSourceDir, portalSourceArchive)
	}); err != nil {
		return fmt.Errorf("archive generated portal: %w", err)
	}
	runtimeVariables["portal_source_dir"] = portalSourceDir
	runtimeVariables["portal_content_digest"] = portalContentDigest
	runtimeVariables["portal_source_archive"] = portalSourceArchive
	runtimeVariables["boetticher_appliance_artifact"] = true
	// Agent installation is enabled only in the post-Pulse bootstrap pass,
	// after the scoped report token and encrypted credential projection exist.
	runtimeVariables["pulse_agent_install_enabled"] = false
	// StreamDeck activation is enabled only in the post-Pulse pass, after its
	// shared read token and encrypted credential projection exist.
	runtimeVariables["streamdeck_runtime_credentials_ready"] = false
	monitoringEnabled := modules.IsEnabled(s, "monitoring")
	aiopsEnabled := modules.IsEnabled(s, "aiops")
	secretValues := map[string]string{}
	platformSecrets, err := site.LoadPlatformSecretCache(*siteDir, s, *ageIdentity)
	if err != nil {
		return fmt.Errorf("load encrypted platform secrets: %w", err)
	}
	if s.Gateway.Mode == model.GatewayModeManaged {
		ddnsTSIG, loadErr := platformSecrets.Get("ddns_tsig_secret")
		if loadErr != nil {
			return fmt.Errorf("load encrypted DDNS TSIG material: %w", loadErr)
		}
		secretValues["firewall-ddns-tsig"] = ddnsTSIG
	}
	if s.Gateway.Mode == model.GatewayModeManaged {
		ruleset, renderErr := renderDeploymentNFTWithResolver(firewallPlan, endpointLookup)
		if renderErr != nil {
			return renderErr
		}
		runtimeVariables["firewall_ruleset"] = ruleset
		runtimeVariables["firewall_ruleset_sha256"] = firewall.RulesetDigest(ruleset)
	}
	authority, err := site.LoadAuthority(*siteDir, s, *ageIdentity)
	if err != nil {
		return fmt.Errorf("load platform CA chain: %w", err)
	}
	revocations, err := site.LoadClientRevocations(*siteDir)
	if err != nil {
		return fmt.Errorf("HOLD: load client revocations: %w", err)
	}
	var clientCRL string
	if err := report.timed("credentials-pki", "local", "client-crl", func() error {
		var crlErr error
		clientCRL, crlErr = generateOrReuseClientCRL(authority, revocations, site.RuntimeDir(s), time.Now().UTC())
		return crlErr
	}); err != nil {
		return fmt.Errorf("HOLD: generate enforceable client revocation list: %w", err)
	}
	runtimeVariables["client_crl_pem"] = clientCRL
	var pulseAdminPassword string
	if monitoringEnabled {
		var loadErr error
		pulseAdminPassword, loadErr = platformSecrets.Get("pulse_admin_password")
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
		value, loadErr := platformSecrets.Get(binding.SecretKey)
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
	} else if proxmoxCredentials, loadErr := site.LoadProxmoxCredentials(*siteDir, s, *ageIdentity); loadErr != nil {
		return fmt.Errorf("load encrypted Proxmox credentials for API trust projection: %w", loadErr)
	} else if proxmoxCredentials.CAPEM != "" {
		runtimeVariables["proxmox_ca_pem"] = proxmoxCredentials.CAPEM
	}
	inventoryPath := filepath.Join(*siteDir, "generated", "ansible", "inventory.ini")
	csrDir := filepath.Join(site.RuntimeDir(s), "pki")
	if err := os.MkdirAll(csrDir, 0700); err != nil {
		return fmt.Errorf("create controller PKI runtime directory: %w", err)
	}
	runtimeVariables["pki_bootstrap_phase"] = true
	runtimeVariables["pki_csr_output_dir"] = csrDir
	if err := report.timed("credentials-pki", "local", "projections", func() error {
		return writeModelProjectionsWithResolverAndAirVPN(*siteDir, s, endpointLookup, airvpnMetadata)
	}); err != nil {
		return err
	}
	report.recordMutation("Generated state", "site projections", "reconciled", true)
	variables, err = json.MarshalIndent(runtimeVariables, "", "  ")
	if err != nil {
		return err
	}
	variables = append(variables, '\n')
	report.complete()
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
	proxmoxPlan.PrivilegedRunner = rootRunner
	proxmoxPlan.PrivilegedAddress = s.BootstrapAddress
	proxmoxPlan.PrivilegedUser = "root"
	rootCleanup := newTemporaryRootCleanup(s, *siteDir, operatorPublicKey)
	registerCleanup(rootCleanup.revoke)
	report.start("proxmox", "Reconcile Proxmox platform and storage")
	if s.Gateway.Mode == model.GatewayModeManaged {
		// Reconcile the live host-side jump policy from the same canonical
		// destination list as the generated projection, including any
		// product-owned retained guests that remain in the SSH contract.
		// Arm cleanup before the remote command because the command can make
		// partial changes before reporting an error.
		rootCleanup.hostEstablished()
		if err := proxmox.ConfigureIdentities(ctx, rootRunner, s.BootstrapAddress, "root", operatorPublicKey, jumpDestinations(s)); err != nil {
			return fmt.Errorf("reconcile Proxmox administrative and bastion identities: %w", err)
		}
	}
	if err := proxmox.WaitForSSH(ctx, rootRunner, s.BootstrapAddress, "root", 1, 0); err != nil {
		return fmt.Errorf("HOLD: temporary root deployment authority is unavailable; rerun bootstrap or recovery: %w", err)
	}
	proxmoxClient, _, err := loadProxmoxClientWithSnippetUser(*siteDir, s, *ageIdentity, *proxmoxCA, *insecure, "root")
	if err != nil {
		return fmt.Errorf("load Proxmox client for platform deployment: %w", err)
	}
	node, err := proxmoxClient.SingleNode(ctx)
	if err != nil {
		return fmt.Errorf("resolve live Proxmox node: %w", err)
	}
	proxmoxPlan.Node = node
	if err := validateLiveDeploymentPrerequisitesWithResolver(ctx, proxmoxClient, rootRunner, *siteDir, s, proxmoxPlan, storagePlan, endpointLookup); err != nil {
		return fmt.Errorf("live preflight failed before Proxmox mutation: %w", err)
	}
	var pulseProxmoxToken string
	if monitoringEnabled {
		pulseProxmoxToken, err = site.LoadPlatformSecret(*siteDir, s, *ageIdentity, "pulse_proxmox_token")
		if errors.Is(err, site.ErrPlatformSecretMissing) {
			pulseProxmoxToken, err = proxmox.CreatePulseMonitoringCredentials(ctx, rootRunner, s.BootstrapAddress, "root")
			if err != nil {
				return err
			}
			if err := site.StorePlatformSecret(*siteDir, s, *ageIdentity, "pulse_proxmox_token", pulseProxmoxToken); err != nil {
				return fmt.Errorf("store encrypted Pulse Proxmox token: %w", err)
			}
			report.recordMutation("Secrets", "pulse_proxmox_token", "credential stored", true)
		} else if err != nil {
			return fmt.Errorf("load encrypted Pulse Proxmox token: %w", err)
		}
	}
	proxmoxPlan.DestructiveConfirmed = *confirm
	if backupPlan.StorageTarget == backup.DedicatedStorageID {
		changed, err := proxmoxClient.EnsureLVMThinStorageWithMutation(ctx, storage.GuestStorageID, storage.VolumeGroup, storage.ThinPool)
		if changed {
			report.recordMutation("Proxmox", storage.GuestStorageID, "guest storage registered", true)
		}
		if err != nil {
			return fmt.Errorf("ensure dedicated guest storage: %w", err)
		}
		changed, err = proxmoxClient.EnsureDirectoryStorageContentWithMutation(ctx, backup.DedicatedStorageID, backup.DedicatedStoragePath, []string{"backup"})
		if changed {
			report.recordMutation("Proxmox", backup.DedicatedStorageID, "backup storage registered", true)
		}
		if err != nil {
			return fmt.Errorf("ensure dedicated backup storage: %w", err)
		}
	} else {
		localContent, contentErr := storage.LocalStorageContent(s.StorageProfile)
		if contentErr != nil {
			return contentErr
		}
		changed, err := proxmoxClient.EnsureDirectoryStorageContentWithMutation(ctx, "local", "/var/lib/vz", localContent)
		if changed {
			report.recordMutation("Proxmox", "local", "storage content reconciled", true)
		}
		if err != nil {
			return fmt.Errorf("ensure local Proxmox storage: %w", err)
		}
	}
	if s.Gateway.Mode == model.GatewayModeManaged {
		firewallGuest := proxmox.GuestPlan{VMID: model.ProxmoxVMID, Name: "lab-fw-01", Hostname: "lab-fw-01", Kind: proxmox.KindQEMU, Address: "10.10.99.1"}
		for _, candidate := range proxmoxPlan.Guests {
			if candidate.Kind == proxmox.KindQEMU {
				firewallGuest = candidate
				break
			}
		}
		firewallExisted, firewallReplaced, stateErr := proxmox.InspectGuestArtifact(ctx, proxmoxClient, proxmoxPlan.Node, firewallGuest)
		if stateErr != nil {
			return stateErr
		}
		if err := report.timed("proxmox", "reconcile", firewallGuest.Name, func() error {
			return proxmox.EnsureFirewallVM(ctx, proxmoxClient, proxmoxPlan)
		}); err != nil {
			if !firewallExisted || firewallReplaced {
				report.markMutationUncertain()
			}
			return fmt.Errorf("create managed gateway appliance: %w", err)
		}
		if !firewallExisted {
			report.recordMutation("Proxmox", firewallGuest.Name, "guest created", true)
		}
		if firewallReplaced {
			report.recordMutation("Proxmox", firewallGuest.Name, "guest replaced", true)
		}
		if firewallReplaced {
			if err := retireReplacedHostKey(*siteDir, s, firewallGuest); err != nil {
				return fmt.Errorf("retire replaced gateway host key: %w", err)
			}
		}
		if err := report.timed("proxmox", "reconcile", firewallGuest.Name+"/start", func() error {
			return proxmoxClient.EnsureVMRunning(ctx, proxmoxPlan.Node, model.ProxmoxVMID)
		}); err != nil {
			return fmt.Errorf("start managed gateway appliance: %w", err)
		}
	}
	report.complete()
	report.start("appliances", "Reconcile appliance guests")
	var firewallRunner proxmox.SSHRunner
	if s.Gateway.Mode == model.GatewayModeManaged {
		firewallRunner = applianceSSHRunner(s, *siteDir, "lab-fw-01")
		firewallGuest := proxmox.GuestPlan{VMID: model.ProxmoxVMID, Name: "lab-fw-01", Hostname: "lab-fw-01", Kind: proxmox.KindQEMU, Address: "10.10.99.1"}
		if err := report.timed("appliances", "readiness", firewallGuest.Name, func() error {
			return waitForDeploymentRoot(ctx, rootRunner, s.BootstrapAddress, firewallRunner.FreshConnection(), firewallGuest, operatorPublicKey, deploymentKnownHosts(*siteDir), firewallGuest.Hostname+"."+s.Network.Domain, func() {
				rootCleanup.guestEstablished(firewallGuest)
			})
		}); err != nil {
			return fmt.Errorf("HOLD: managed gateway is not reachable before dependent appliances: %w", err)
		}
		if err := verifyFirewallBootstrapNetwork(ctx, firewallRunner); err != nil {
			return fmt.Errorf("HOLD: managed gateway bootstrap network is not ready before runtime configuration: %w", err)
		}
		if err := installCredentialsForGuest(ctx, firewallRunner, "lab-fw-01", credentialBindings, secretValues); err != nil {
			return fmt.Errorf("install managed gateway credentials: %w", err)
		}
		if err := runTrackedAnsible(ctx, ansiblePlaybook, inventoryPath, variables, "lab-fw-01", report); err != nil {
			return fmt.Errorf("HOLD: configure managed gateway before dependent appliances: %w", err)
		}
		if err := report.timed("appliances", "readiness", firewallGuest.Name+"/gateway", func() error {
			return verifyGatewayReadiness(ctx, firewallRunner, "10.10.99.1")
		}); err != nil {
			return fmt.Errorf("HOLD: managed gateway did not pass runtime readiness before dependent appliances: %w", err)
		}
	}
	guestStates := map[int]deploymentGuestArtifactState{}
	if err := report.timed("appliances", "preflight", "guest-state", func() error {
		var err error
		guestStates, err = inspectDeploymentGuestStates(ctx, proxmoxClient, proxmoxPlan.Node, deploymentGuestPlans(s, proxmoxPlan))
		return err
	}); err != nil {
		return err
	}
	dnsPlan, err := dns.PlanFromSite(s)
	if err != nil {
		return fmt.Errorf("resolve DNS readiness contract: %w", err)
	}
	for _, module := range deploymentModuleNames(s) {
		if !modules.IsEnabled(s, module) && module != "portal" {
			continue
		}
		replacedGuests := make([]proxmox.GuestPlan, 0)
		missingGuests := make([]proxmox.GuestPlan, 0)
		for _, candidate := range proxmoxPlan.Guests {
			matches := candidate.Owner == "boetticher/module/"+module
			if module == "portal" {
				matches = candidate.Name == "lab-portal-01"
			}
			if !matches || candidate.Kind != proxmox.KindLXC {
				continue
			}
			state, ok := guestStates[candidate.VMID]
			if !ok {
				return fmt.Errorf("inspect %s state: guest was not included in preflight", candidate.Name)
			}
			existed, replacement := state.exists, state.replacement
			if replacement {
				replacedGuests = append(replacedGuests, candidate)
			}
			if !existed {
				missingGuests = append(missingGuests, candidate)
			}
		}
		if err := report.timed("appliances", "proxmox", module, func() error {
			return proxmox.ProvisionModule(ctx, proxmoxClient, proxmoxPlan, module)
		}); err != nil {
			if len(missingGuests) > 0 || len(replacedGuests) > 0 {
				report.markMutationUncertain()
			}
			return fmt.Errorf("deploy %s appliances: %w", module, err)
		}
		for _, guest := range missingGuests {
			report.recordMutation("Proxmox", guest.Name, "guest created", true)
		}
		for _, guest := range replacedGuests {
			report.recordMutation("Proxmox", guest.Name, "guest replaced", true)
		}
		for _, guest := range replacedGuests {
			if err := retireReplacedHostKey(*siteDir, s, guest); err != nil {
				return fmt.Errorf("retire replaced %s host key: %w", guest.Name, err)
			}
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
			if err := report.timed("appliances", "readiness", guest.Name, func() error {
				return waitForDeploymentRoot(ctx, rootRunner, s.BootstrapAddress, guestRunner.FreshConnection(), guest, operatorPublicKey, deploymentKnownHosts(*siteDir), guest.Hostname+"."+s.Network.Domain, func() {
					rootCleanup.guestEstablished(guest)
				})
			}); err != nil {
				return fmt.Errorf("HOLD: %s guest %s is not reachable after first boot: %w", module, guest.Name, err)
			}
			if err := installCredentialsForGuest(ctx, guestRunner, guest.Name, credentialBindings, secretValues); err != nil {
				return fmt.Errorf("install %s credentials: %w", guest.Name, err)
			}
			if module == "dns" {
				state := guestStates[guest.VMID]
				if needsInitialDNSConfiguration(state) {
					if err := runTrackedAnsible(ctx, ansiblePlaybook, inventoryPath, variables, guest.Name, report); err != nil {
						return fmt.Errorf("HOLD: configure DNS guest %s before dependent appliances: %w", guest.Name, err)
					}
				}
				if guest.Name == "lab-dns-01" && s.Gateway.Mode == model.GatewayModeManaged {
					needsRestart, err := installPowerDNSTSIG(ctx, guestRunner, guest.Address, dnsPlan, secretValues["firewall-ddns-tsig"])
					if err != nil {
						return fmt.Errorf("install PowerDNS TSIG state on %s: %w", guest.Name, err)
					}
					if !needsRestart {
						needsRestart, err = powerDNSTSIGSyncMarkerMissing(ctx, guestRunner, guest.Address)
						if err != nil {
							return fmt.Errorf("check PowerDNS TSIG synchronization on %s: %w", guest.Name, err)
						}
					}
					if needsRestart {
						if err := restartPowerDNSAfterTSIG(ctx, guestRunner, guest.Address); err != nil {
							return fmt.Errorf("restart PowerDNS after TSIG state change on %s: %w", guest.Name, err)
						}
					}
				}
				if err := report.timed("appliances", "readiness", guest.Name+"/dns", func() error {
					return verifyDNSReadiness(ctx, guestRunner, guest.Address)
				}); err != nil {
					return fmt.Errorf("HOLD: DNS guest %s did not pass runtime readiness before dependent appliances: %w", guest.Name, err)
				}
			}
		}
		if module == "dns" && s.Gateway.Mode == model.GatewayModeManaged && len(firewallPlan.Publications) > 0 {
			var upstream firewall.UpstreamObservation
			if err := report.timed("network", "ssh", "gateway-upstream", func() error {
				var observeErr error
				upstream, observeErr = observeGatewayUpstream(ctx, firewallRunner, firewallPlan)
				return observeErr
			}); err != nil {
				return fmt.Errorf("HOLD: published services require a safe current upstream DHCP lease: %w", err)
			}
			var finalFirewallPlan firewall.Plan
			var planErr error
			if airvpnMetadata == nil {
				finalFirewallPlan, planErr = firewall.PlanFromSiteWithUpstream(s, upstream)
			} else {
				finalFirewallPlan, planErr = firewall.PlanFromSiteWithUpstreamAndAirVPN(s, upstream, *airvpnMetadata)
			}
			if planErr != nil {
				return fmt.Errorf("HOLD: resolve published service policy from upstream lease: %w", planErr)
			}
			if airvpnMetadata != nil {
				if err := report.timed("network", "provider", "airvpn-endpoint", func() error {
					var bindErr error
					finalFirewallPlan, bindErr = firewall.BindAirVPNEndpoint(finalFirewallPlan, endpointLookup)
					return bindErr
				}); err != nil {
					return fmt.Errorf("HOLD: resolve AirVPN provider endpoint: %w", err)
				}
				airvpnMetadata = finalFirewallPlan.AirVPN
			}
			finalRuleset, renderErr := renderDeploymentNFTWithResolver(finalFirewallPlan, endpointLookup)
			if renderErr != nil {
				return fmt.Errorf("HOLD: render published service policy: %w", renderErr)
			}
			var finalVariables []byte
			var variablesErr error
			if airvpnMetadata == nil {
				finalVariables, variablesErr = ansible.VariablesWithOperatorKeyAndUpstream(s, upstream, operatorPublicKey)
			} else {
				finalVariables, variablesErr = ansible.VariablesWithOperatorKeyAndUpstreamAndAirVPN(s, upstream, operatorPublicKey, *airvpnMetadata)
			}
			if variablesErr != nil {
				return fmt.Errorf("HOLD: render published service Ansible variables: %w", variablesErr)
			}
			var finalVariableDocument map[string]any
			if err := json.Unmarshal(finalVariables, &finalVariableDocument); err != nil {
				return fmt.Errorf("HOLD: decode published service Ansible variables: %w", err)
			}
			runtimeVariables["firewall_plan"] = finalVariableDocument["firewall_plan"]
			runtimeVariables["firewall_interface_config_digests"] = finalVariableDocument["firewall_interface_config_digests"]
			runtimeVariables["firewall_ruleset"] = finalRuleset
			runtimeVariables["firewall_ruleset_sha256"] = firewall.RulesetDigest(finalRuleset)
			variables, err = json.MarshalIndent(runtimeVariables, "", "  ")
			if err != nil {
				return fmt.Errorf("HOLD: encode published service Ansible variables: %w", err)
			}
			variables = append(variables, '\n')
			if err := runTrackedAnsible(ctx, ansiblePlaybook, inventoryPath, variables, "lab-fw-01", report); err != nil {
				return fmt.Errorf("HOLD: activate published services on managed gateway: %w", err)
			}
			if err := report.timed("network", "readiness", "lab-fw-01/gateway", func() error {
				return verifyGatewayReadiness(ctx, firewallRunner, "10.10.99.1")
			}); err != nil {
				return fmt.Errorf("HOLD: managed gateway did not pass publication readiness: %w", err)
			}
			firewallPlan = finalFirewallPlan
			// The final limited pass has already converged the firewall using the
			// observed upstream lease. Do not immediately run that same role
			// again in the all-host network phase.
			runtimeVariables["boetticher_skip_firewall"] = true
			variables, err = json.MarshalIndent(runtimeVariables, "", "  ")
			if err != nil {
				return fmt.Errorf("HOLD: encode network-phase Ansible variables: %w", err)
			}
			variables = append(variables, '\n')
		}
	}
	for _, guest := range retainedGuests {
		module := strings.TrimPrefix(guest.Owner, "boetticher/module/")
		if err := proxmox.InactivateRetainedModule(ctx, rootRunner, s.BootstrapAddress, "root", guest.Kind, guest.VMID, module); err != nil {
			return fmt.Errorf("HOLD: inactivate retained %s guest %s through Proxmox: %w", module, guest.Name, err)
		}
	}
	report.complete()
	report.start("network", "Reconcile network and DNS")
	if err := runTrackedAnsiblePhase(ctx, ansiblePlaybook, inventoryPath, variables, "", ansible.PhaseBootstrap, report); err != nil {
		return err
	}
	report.complete()
	report.start("services", "Configure services and runtime credentials")
	loggingClientCertificates, loggingCollectorCertificate, err := signLoggingCertificates(authority, s, csrDir)
	if err != nil {
		return fmt.Errorf("sign logging transport certificates: %w", err)
	}
	if err := installModuleRuntimeConfigs(ctx, *siteDir, s, proxmoxPlan); err != nil {
		return err
	}
	report.recordMutation("Services", "appliance runtime configuration", "reconciled", true)
	portalCSR, err := os.ReadFile(filepath.Join(csrDir, "portal.csr.pem"))
	if err != nil {
		return fmt.Errorf("read endpoint-generated portal CSR: %w", err)
	}
	var monitorCertificate pki.ServerCertificate
	var bifrostCertificate pki.ServerCertificate
	var octoprintCertificate pki.ServerCertificate
	var streamDeckCertificate pki.ClientCertificate
	var gatusCertificate pki.ServerCertificate
	var aiopsCertificates map[string]string
	if monitoringEnabled {
		monitorCSR, readErr := os.ReadFile(filepath.Join(csrDir, "monitor.csr.pem"))
		if readErr != nil {
			return fmt.Errorf("read endpoint-generated monitor CSR: %w", readErr)
		}
		monitorCertificate, err = signOrReuseServerCertificate(authority, string(monitorCSR), csrDir, "monitor", "monitor", s.Network.Domain, []string{"lab-monitor-01." + s.Network.Domain})
		if err != nil {
			return fmt.Errorf("sign monitor endpoint CSR: %w", err)
		}
	}
	if modules.IsEnabled(s, "bifrost") {
		bifrostCSR, readErr := os.ReadFile(filepath.Join(csrDir, "bifrost.csr.pem"))
		if readErr != nil {
			return fmt.Errorf("read endpoint-generated Bifrost CSR: %w", readErr)
		}
		bifrostCertificate, err = signOrReuseServerCertificate(authority, string(bifrostCSR), csrDir, "bifrost", "bifrost", s.Network.Domain, []string{"ai." + s.Network.Domain, "lab-bifrost-01." + s.Network.Domain})
		if err != nil {
			return fmt.Errorf("sign Bifrost endpoint CSR: %w", err)
		}
	}
	if modules.IsEnabled(s, "printer") {
		octoprintCSR, readErr := os.ReadFile(filepath.Join(csrDir, "octoprint.csr.pem"))
		if readErr != nil {
			return fmt.Errorf("read endpoint-generated OctoPrint CSR: %w", readErr)
		}
		octoprintCertificate, err = signOrReuseServerCertificate(authority, string(octoprintCSR), csrDir, "octoprint", "octoprint", s.Network.Domain, []string{"printer." + s.Network.Domain, "lab-printer-01." + s.Network.Domain})
		if err != nil {
			return fmt.Errorf("sign OctoPrint endpoint CSR: %w", err)
		}
	}
	if modules.IsEnabled(s, "streamdeck") {
		streamDeckCSR, readErr := os.ReadFile(filepath.Join(csrDir, "streamdeck.csr.pem"))
		if readErr != nil {
			return fmt.Errorf("read endpoint-generated StreamDeck CSR: %w", readErr)
		}
		streamDeckCertificate, err = signOrReuseServiceClientCertificate(authority, string(streamDeckCSR), csrDir, "streamdeck", "lab-streamdeck-01")
		if err != nil {
			return fmt.Errorf("sign StreamDeck client CSR: %w", err)
		}
	}
	if modules.IsEnabled(s, "aiops") {
		aiopsCertificates, err = signAIOpsCertificates(authority, s, csrDir)
		if err != nil {
			return fmt.Errorf("sign AIOps endpoint certificates: %w", err)
		}
	}
	if modules.IsEnabled(s, "gatus") {
		csr, readErr := os.ReadFile(filepath.Join(csrDir, "gatus.csr.pem"))
		if readErr != nil {
			return fmt.Errorf("read endpoint-generated Gatus CSR: %w", readErr)
		}
		gatusCertificate, err = signOrReuseServerCertificate(authority, string(csr), csrDir, "gatus", "gatus", s.Network.Domain, []string{"lab-gatus-01." + s.Network.Domain})
		if err != nil {
			return fmt.Errorf("sign Gatus endpoint CSR: %w", err)
		}
	}
	portalCertificate, err := signOrReuseServerCertificate(authority, string(portalCSR), csrDir, "portal", "portal", s.Network.Domain, []string{"lab-portal-01." + s.Network.Domain})
	if err != nil {
		return fmt.Errorf("sign portal endpoint CSR: %w", err)
	}
	runtimeVariables["pki_bootstrap_phase"] = false
	if monitoringEnabled {
		runtimeVariables["monitor_server_cert_pem"] = monitorCertificate.ChainPEM
	}
	if modules.IsEnabled(s, "bifrost") {
		runtimeVariables["bifrost_server_cert_pem"] = bifrostCertificate.ChainPEM
	}
	if modules.IsEnabled(s, "printer") {
		runtimeVariables["octoprint_server_cert_pem"] = octoprintCertificate.ChainPEM
	}
	if modules.IsEnabled(s, "streamdeck") {
		runtimeVariables["streamdeck_client_cert_pem"] = streamDeckCertificate.ChainPEM
	}
	if modules.IsEnabled(s, "gatus") {
		runtimeVariables["gatus_server_cert_pem"] = gatusCertificate.ChainPEM
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
	if err := runTrackedAnsiblePhase(ctx, ansiblePlaybook, inventoryPath, variables, "", ansible.PhaseServices, report); err != nil {
		return fmt.Errorf("install endpoint-signed certificates: %w", err)
	}
	report.complete()
	report.start("health", "Run live health gates")
	var pulseForward *proxmox.SSHLocalForward
	var aiRouterForward *proxmox.SSHLocalForward
	defer func() {
		if pulseForward != nil {
			_ = pulseForward.Close()
		}
		if aiRouterForward != nil {
			_ = aiRouterForward.Close()
		}
	}()
	if monitoringEnabled {
		bastionRunner := proxmoxBastionSSHRunner(s, *siteDir)
		pulseRunner := bastionRunner
		pulseForward, err = pulseRunner.StartLocalForward(ctx, s.BootstrapAddress, "lab-jump", "10.10.10.20", 443)
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
			aiRouterForward, err = bastionRunner.StartLocalForward(ctx, s.BootstrapAddress, "lab-jump", "10.10.20.60", 443)
			if err != nil {
				return fmt.Errorf("open AI Router canary tunnel through Proxmox bastion: %w", err)
			}
			if err := qualifyAndConfigureAIOps(ctx, *siteDir, *ageIdentity, s, authority, clientCertificate, pulseAdmin, pulseBaseURL, aiRouterForward.Address(), runtimeVariables, ansiblePlaybook, inventoryPath, report); err != nil {
				return fmt.Errorf("HOLD: AIOps qualification failed: %w", err)
			}
		}
		if err := pulseAdmin.ConfigureProxmox(ctx, pulse.PVEConfig{
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
			readToken, tokenErr = pulseAdmin.CreateReadToken(ctx, "boetticher monitoring read")
			if tokenErr != nil {
				return tokenErr
			}
			if err := site.StorePlatformSecret(*siteDir, s, *ageIdentity, "pulse_api_token", readToken); err != nil {
				return fmt.Errorf("store encrypted Pulse read token: %w", err)
			}
			report.recordMutation("Secrets", "pulse_api_token", "credential stored", true)
		} else if tokenErr != nil {
			return fmt.Errorf("load encrypted Pulse read token: %w", tokenErr)
		}
		readClientCertificate, clientErr := pki.IssueClient(authority, "boetticher-pulse-read", s.Network.Domain, time.Now().UTC())
		if clientErr != nil {
			return fmt.Errorf("issue Pulse read client certificate: %w", clientErr)
		}
		pulseRead, clientErr := pulse.NewReadClient(pulse.ClientConfig{
			BaseURL: pulseBaseURL, APIToken: readToken,
			CAPEM: authority.IssuingCertPEM, ClientCertPEM: readClientCertificate.CertPEM, ClientKeyPEM: readClientCertificate.KeyPEM,
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
			readToken, tokenErr = pulseAdmin.CreateReadToken(ctx, "boetticher monitoring read")
			if tokenErr != nil {
				return tokenErr
			}
			if err := site.StorePlatformSecret(*siteDir, s, *ageIdentity, "pulse_api_token", readToken); err != nil {
				return fmt.Errorf("store encrypted Pulse read token: %w", err)
			}
			report.recordMutation("Secrets", "pulse_api_token", "credential refreshed", true)
			pulseRead, clientErr = pulse.NewReadClient(pulse.ClientConfig{
				BaseURL: pulseBaseURL, APIToken: readToken,
				CAPEM: authority.IssuingCertPEM, ClientCertPEM: readClientCertificate.CertPEM, ClientKeyPEM: readClientCertificate.KeyPEM,
				ServerName: "monitor." + s.Network.Domain,
			})
			if clientErr != nil {
				return clientErr
			}
			readTokenRefreshed = true
			return nil
		}
		var health pulse.HealthStatus
		err = report.timed("health", "health", "pulse", func() error {
			var healthErr error
			health, healthErr = pulseRead.Health(ctx)
			return healthErr
		})
		if err != nil {
			if !(modules.IsEnabled(s, "streamdeck") && pulse.IsForbidden(err)) {
				return fmt.Errorf("verify Pulse health: %w", err)
			}
			if refreshErr := refreshPulseReadToken(); refreshErr != nil {
				return fmt.Errorf("refresh Pulse read token after forbidden health response: %w", refreshErr)
			}
			err = report.timed("health", "health", "pulse-refresh", func() error {
				var healthErr error
				health, healthErr = pulseRead.Health(ctx)
				return healthErr
			})
			if err != nil {
				return fmt.Errorf("verify Pulse health after read-token refresh: %w", err)
			}
		}
		if !strings.EqualFold(health.Status, "healthy") {
			return fmt.Errorf("verify Pulse health: unexpected status %q", health.Status)
		}
		if _, err := pulseRead.StateSummary(ctx); err != nil {
			if !pulse.IsUnauthorized(err) {
				return fmt.Errorf("verify Pulse state summary: %w", err)
			}
			if refreshErr := refreshPulseReadToken(); refreshErr != nil {
				return fmt.Errorf("refresh Pulse read token after unauthorized response: %w", refreshErr)
			}
			if _, retryErr := pulseRead.StateSummary(ctx); retryErr != nil {
				return fmt.Errorf("verify Pulse state summary after read-token refresh: %w", retryErr)
			}
		}
		if _, err := pulseRead.Resources(ctx); err != nil {
			if !pulse.IsUnauthorized(err) || readTokenRefreshed {
				return fmt.Errorf("verify Pulse resources: %w", err)
			}
			if refreshErr := refreshPulseReadToken(); refreshErr != nil {
				return fmt.Errorf("refresh Pulse read token after unauthorized response: %w", refreshErr)
			}
			if _, retryErr := pulseRead.Resources(ctx); retryErr != nil {
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
				agentToken, agentTokenErr = pulseAdmin.CreateAgentReportToken(ctx, "boetticher monitoring agent")
				if agentTokenErr != nil {
					return agentTokenErr
				}
				if err := site.StorePlatformSecret(*siteDir, s, *ageIdentity, "pulse_agent_token", agentToken); err != nil {
					return fmt.Errorf("store encrypted Pulse agent token: %w", err)
				}
				report.recordMutation("Secrets", "pulse_agent_token", "credential stored", true)
			} else if agentTokenErr != nil {
				return fmt.Errorf("load encrypted Pulse agent token: %w", agentTokenErr)
			}

			for _, target := range ansible.MonitoringAgentTargets(s) {
				var agentRunner proxmox.CommandRunner
				if target == model.LogicalProxmoxIdentity {
					agentRunner = proxmox.SSHRunner{
						IdentityFile:  operatorIdentityFile(s),
						ConfigFile:    filepath.Join(*siteDir, "generated", "ssh", "boetticher.conf"),
						StrictHostKey: "yes", HostKeyAlias: model.LogicalProxmoxIdentity,
					}
				} else {
					agentRunner = applianceSSHRunner(s, *siteDir, target)
				}
				if err := installCredentialsForGuest(ctx, agentRunner, target, agentBindings, map[string]string{"pulse_agent_token": agentToken}); err != nil {
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
				if err := runTrackedAnsible(ctx, ansiblePlaybook, inventoryPath, agentVariables, target, report); err != nil {
					return fmt.Errorf("install Pulse agent on %s: %w", target, err)
				}
			}
		}

		streamDeckBindings, bindingErr := streamDeckCredentialBindings(s)
		if bindingErr != nil {
			return bindingErr
		}
		if len(streamDeckBindings) > 0 {
			streamDeckRunner := applianceSSHRunner(s, *siteDir, "lab-streamdeck-01")
			if err := installCredentialsForGuest(ctx, streamDeckRunner, "lab-streamdeck-01", streamDeckBindings, map[string]string{"pulse_api_token": readToken}); err != nil {
				return fmt.Errorf("install StreamDeck Pulse credential: %w", err)
			}
			streamDeckDropIns, dropInErr := credentialDropIns(streamDeckBindings)
			if dropInErr != nil {
				return dropInErr
			}
			existingDropIns, ok := runtimeVariables["credential_dropins"].(map[string]map[string]string)
			if !ok {
				existingDropIns = map[string]map[string]string{}
			}
			for guest, dropIns := range streamDeckDropIns {
				if existingDropIns[guest] == nil {
					existingDropIns[guest] = map[string]string{}
				}
				for unit, content := range dropIns {
					existingDropIns[guest][unit] = content
				}
			}
			runtimeVariables["credential_dropins"] = existingDropIns
			runtimeVariables["streamdeck_runtime_credentials_ready"] = true
			streamDeckVariables, marshalErr := json.MarshalIndent(runtimeVariables, "", "  ")
			if marshalErr != nil {
				return marshalErr
			}
			streamDeckVariables = append(streamDeckVariables, '\n')
			if err := runTrackedAnsiblePhase(ctx, ansiblePlaybook, inventoryPath, streamDeckVariables, "lab-streamdeck-01", ansible.PhaseHealth, report); err != nil {
				return fmt.Errorf("install StreamDeck runtime: %w", err)
			}
		}
	}
	if pulseForward != nil {
		if err := pulseForward.Close(); err != nil {
			return fmt.Errorf("close Pulse API tunnel: %w", err)
		}
		pulseForward = nil
	}
	report.complete()
	report.start("persist", "Persist final state")
	backupChanged, err := proxmoxClient.ApplyBackupJobWithMutation(ctx, node, proxmox.BackupJob{
		JobName: backupPlan.JobName, ModelRevision: backupPlan.ModelRevision, StorageTarget: backupPlan.StorageTarget,
		Schedule: backupPlan.Schedule, VMIDList: backupPlan.VMIDList(), Retention: backupPlan.Retention,
	})
	if backupChanged {
		report.recordMutation("Proxmox", backupPlan.JobName, "backup job reconciled", true)
	}
	if err != nil {
		return err
	}
	if len(s.PendingDNSDeletions) > 0 {
		if err := site.SavePendingDNSDeletions(*siteDir, s, nil); err != nil {
			return fmt.Errorf("clear reconciled DNS deletion state: %w", err)
		}
		s.PendingDNSDeletions = nil
	}
	if err := report.timed("persist", "local", "projections", func() error {
		return writeModelProjectionsWithResolverAndAirVPN(*siteDir, s, endpointLookup, airvpnMetadata)
	}); err != nil {
		return err
	}
	report.recordMutation("Generated state", "site projections", "persisted", true)
	if err := report.timed("persist", "local", "portal", func() error {
		return rebuildPortal(*siteDir, s)
	}); err != nil {
		return err
	}
	report.complete()
	return nil
}

const deploymentRootTimeout = 3 * time.Minute

func waitForDeploymentRoot(ctx context.Context, hostRunner proxmox.CommandRunner, hostAddress string, guestRunner proxmox.CommandRunner, guest proxmox.GuestPlan, publicKey, knownHosts, hostKeyAlias string, onAuthorityEstablished ...func()) error {
	if guest.Hostname == "" || hostKeyAlias == "" {
		return errors.New("guest host-key identity is incomplete")
	}
	markAuthorityEstablished := func() {
		if len(onAuthorityEstablished) > 0 && onAuthorityEstablished[0] != nil {
			onAuthorityEstablished[0]()
		}
	}
	rootCtx, cancel := context.WithTimeout(ctx, deploymentRootTimeout)
	defer cancel()
	var hostKey string
	var pinErr error
	for attempt := 0; attempt < 30; attempt++ {
		hostKey, pinErr = proxmox.ReadGuestHostKey(rootCtx, hostRunner, hostAddress, "root", guest.Kind, guest.VMID)
		if pinErr == nil {
			break
		}
		if attempt+1 < 30 {
			timer := time.NewTimer(2 * time.Second)
			select {
			case <-rootCtx.Done():
				timer.Stop()
				return fmt.Errorf("guest host-key pinning cancelled: %w", rootCtx.Err())
			case <-timer.C:
			}
		}
	}
	if pinErr != nil {
		return fmt.Errorf("HOLD: independently read guest host key through Proxmox: %w", pinErr)
	}
	if err := sshconfig.AddHostKey(knownHosts, hostKeyAlias, hostKey); err != nil {
		return fmt.Errorf("HOLD: pin guest host key: %w", err)
	}
	if err := proxmox.WaitForSSH(rootCtx, guestRunner, guest.Address, "root", 1, 0); err == nil {
		markAuthorityEstablished()
		return nil
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(2 * time.Second)
			select {
			case <-rootCtx.Done():
				timer.Stop()
				return fmt.Errorf("initial root transport failed and guest re-arm cancelled: %w", rootCtx.Err())
			case <-timer.C:
			}
		}
		if restoreErr := proxmox.RestoreTemporaryRootAccess(rootCtx, hostRunner, hostAddress, "root", guest.Kind, guest.VMID, publicKey); restoreErr != nil {
			lastErr = restoreErr
			continue
		}
		// Restoration itself establishes cleanup responsibility. The guest
		// probe may still fail, but the temporary key must be removed on the
		// outer failure path in that case too.
		markAuthorityEstablished()
		if retryErr := proxmox.WaitForSSH(rootCtx, guestRunner, guest.Address, "root", 30, 2*time.Second); retryErr == nil {
			return nil
		} else {
			lastErr = retryErr
		}
	}
	return fmt.Errorf("initial root transport failed after bounded guest re-arm attempts: %w", lastErr)
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
		return "FAIL (qualified content evidence absent)"
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

type deploymentGuestArtifactState struct {
	exists      bool
	replacement bool
}

// needsInitialDNSConfiguration keeps the dependency barrier for new or
// replaced DNS guests while avoiding a duplicate full role pass for an
// unchanged guest. The authoritative all-host network convergence still runs
// after appliance reconciliation and applies current desired state.
func needsInitialDNSConfiguration(state deploymentGuestArtifactState) bool {
	return !state.exists || state.replacement
}

func deploymentGuestPlans(s model.Site, plan proxmox.Plan) []proxmox.GuestPlan {
	seen := make(map[int]bool)
	guests := make([]proxmox.GuestPlan, 0, len(plan.Guests))
	for _, module := range deploymentModuleNames(s) {
		for _, guest := range plan.Guests {
			matches := guest.Owner == "boetticher/module/"+module
			if module == "portal" {
				matches = guest.Name == "lab-portal-01"
			}
			if !matches || guest.Kind != proxmox.KindLXC || seen[guest.VMID] {
				continue
			}
			seen[guest.VMID] = true
			guests = append(guests, guest)
		}
	}
	return guests
}

func inspectDeploymentGuestStates(ctx context.Context, client *proxmox.Client, node string, guests []proxmox.GuestPlan) (map[int]deploymentGuestArtifactState, error) {
	if client == nil {
		return nil, errors.New("Proxmox client is required")
	}
	if node == "" {
		return nil, errors.New("Proxmox node is required")
	}
	if len(guests) == 0 {
		return map[int]deploymentGuestArtifactState{}, nil
	}
	type result struct {
		index       int
		exists      bool
		replacement bool
		err         error
	}
	jobs := make(chan int, len(guests))
	results := make(chan result, len(guests))
	for index := range guests {
		jobs <- index
	}
	close(jobs)
	workers := 4
	if len(guests) < workers {
		workers = len(guests)
	}
	var wait sync.WaitGroup
	wait.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer wait.Done()
			for index := range jobs {
				exists, replacement, err := proxmox.InspectGuestArtifact(ctx, client, node, guests[index])
				results <- result{index: index, exists: exists, replacement: replacement, err: err}
			}
		}()
	}
	wait.Wait()
	close(results)
	ordered := make([]result, len(guests))
	for item := range results {
		ordered[item.index] = item
	}
	states := make(map[int]deploymentGuestArtifactState, len(guests))
	for _, item := range ordered {
		if item.err != nil {
			return nil, item.err
		}
		if _, duplicate := states[guests[item.index].VMID]; duplicate {
			return nil, fmt.Errorf("duplicate deployment guest VMID %d", guests[item.index].VMID)
		}
		states[guests[item.index].VMID] = deploymentGuestArtifactState{exists: item.exists, replacement: item.replacement}
	}
	return states, nil
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
	command := "set -eu; nft -c -f /etc/nftables.conf; test -n \"$(ip -4 -o addr show dev wan0 scope global)\"; ip -4 route show default dev wan0 | grep -Fq default; systemctl is-active nftables kea-dhcp4-server kea-dhcp-ddns-server dnsmasq chrony; test \"$(sysctl -n net.ipv4.ip_forward)\" = 1"
	if _, err := runner.Run(ctx, address, "root", command); err != nil {
		return fmt.Errorf("gateway policy, DHCP, NTP, and forwarding checks failed: %w", err)
	}
	return nil
}

func observeGatewayUpstream(ctx context.Context, runner proxmox.CommandRunner, plan firewall.Plan) (firewall.UpstreamObservation, error) {
	if runner == nil {
		return firewall.UpstreamObservation{}, errors.New("gateway observation runner is required")
	}
	data, err := runner.Run(ctx, "10.10.99.1", "root", "/usr/lib/boetticher/inspect-firewall status")
	if err != nil {
		return firewall.UpstreamObservation{}, err
	}
	status, err := parseGatewayStatus(string(data))
	if err != nil {
		return firewall.UpstreamObservation{}, err
	}
	if err := firewall.ValidateUpstreamObservation(plan, status.Upstream); err != nil {
		return firewall.UpstreamObservation{}, err
	}
	return status.Upstream, nil
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

func verifyDNSReadiness(ctx context.Context, runner proxmox.CommandRunner, address string) error {
	if runner == nil {
		return errors.New("DNS readiness runner is required")
	}
	command := "set -eu; systemctl is-active pdns chrony blocky; test -s /etc/powerdns/pdns.conf; test -s /etc/blocky/config.yml; blocky version | grep -Fq '0.34.0'; blocky validate --config /etc/blocky/config.yml"
	if _, err := runner.Run(ctx, address, "root", command); err != nil {
		return fmt.Errorf("authoritative, NTP, and Blocky resolver checks failed: %w", err)
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
		certificate, err := signOrReuseEndpointClientCertificate(authority, string(csr), csrDir, "logging-"+component.Name, component.Name, s.Network.Domain)
		if err != nil {
			return nil, "", fmt.Errorf("sign %s logging CSR: %w", component.Name, err)
		}
		clients[component.Name] = certificate.ChainPEM
	}
	collectorCSR, err := os.ReadFile(filepath.Join(csrDir, "logging-collector.csr.pem"))
	if err != nil {
		return nil, "", fmt.Errorf("read logging collector CSR: %w", err)
	}
	collector, err := signOrReuseServerCertificate(authority, string(collectorCSR), csrDir, "logging-collector", "logs", s.Network.Domain, []string{"lab-log-01." + s.Network.Domain})
	if err != nil {
		return nil, "", fmt.Errorf("sign logging collector CSR: %w", err)
	}
	return clients, collector.ChainPEM, nil
}

func signAIOpsCertificates(authority pki.Authority, s model.Site, csrDir string) (map[string]string, error) {
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
		certificate, err := signOrReuseServerCertificate(authority, csr, csrDir, request.file, request.identity, s.Network.Domain, request.aliases)
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
		certificate, err := signOrReuseServiceClientCertificate(authority, csr, csrDir, request.file, request.identity)
		if err != nil {
			return nil, fmt.Errorf("sign %s CSR: %w", request.file, err)
		}
		result[request.variable] = certificate.ChainPEM
	}
	return result, nil
}

func qualifyAndConfigureAIOps(ctx context.Context, siteDir, ageIdentity string, s model.Site, authority pki.Authority, controllerCertificate pki.ClientCertificate, pulseAdmin *pulse.Client, pulseBaseURL, routerForwardAddress string, runtimeVariables map[string]any, ansiblePlaybook, inventoryPath string, report *deploymentReport) error {
	modelConfig, err := selectedAIOpsModel(s)
	if err != nil {
		return err
	}
	runner := applianceSSHRunner(s, siteDir, "lab-bifrost-01")
	var metadata []byte
	err = report.timed("health", "health", "bifrost", func() error {
		var metadataErr error
		metadata, metadataErr = runner.RunArgs(ctx, "10.10.20.60", "root", []string{"/usr/local/libexec/boetticher-bifrost-model-capabilities", modelConfig.Alias})
		return metadataErr
	})
	if err != nil {
		return fmt.Errorf("read pinned Bifrost model metadata: %w", err)
	}
	if _, err := aiopsmodel.DecodeModelCapabilities(metadata); err != nil {
		return err
	}
	routerClient, err := controllerMTLSClient(authority, controllerCertificate, routerForwardAddress)
	if err != nil {
		return err
	}
	canaryContext, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if err := report.timed("health", "health", "aiops", func() error {
		return aiopsmodel.QualifyModelAlias(canaryContext, routerClient, "https://ai."+s.Network.Domain+"/v1/chat/completions", s.ModuleConfig["aiops"].ModelAlias)
	}); err != nil {
		return err
	}

	webhookSecret, created, err := loadOrCreateAIOpsSecret(siteDir, ageIdentity, s, "aiops_webhook_secret")
	if err != nil {
		return err
	}
	if created {
		report.recordMutation("Secrets", "aiops_webhook_secret", "credential stored", true)
	}
	readToken, created, err := loadOrCreatePulseToken(siteDir, ageIdentity, s, "aiops_pulse_read_token", func() (string, error) {
		return pulseAdmin.CreateReadToken(ctx, "boetticher aiops read")
	})
	if err != nil {
		return err
	}
	pulseReadCertificate, err := pki.IssueClient(authority, "boetticher-pulse-read", s.Network.Domain, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("issue AIOps Pulse read client certificate: %w", err)
	}
	pulseRead, err := pulse.NewReadClient(pulse.ClientConfig{
		BaseURL: pulseBaseURL, APIToken: readToken,
		CAPEM: authority.IssuingCertPEM, ClientCertPEM: pulseReadCertificate.CertPEM, ClientKeyPEM: pulseReadCertificate.KeyPEM,
		ServerName: "monitor." + s.Network.Domain,
	})
	if err != nil {
		return fmt.Errorf("configure AIOps Pulse read client: %w", err)
	}
	if _, err := pulseRead.StateSummary(ctx); err != nil {
		if !pulse.IsUnauthorized(err) {
			return fmt.Errorf("validate AIOps Pulse read token: %w", err)
		}
		readToken, err = pulseAdmin.CreateReadToken(ctx, "boetticher aiops read")
		if err != nil {
			return fmt.Errorf("refresh AIOps Pulse read token: %w", err)
		}
		if err := site.StorePlatformSecret(siteDir, s, ageIdentity, "aiops_pulse_read_token", readToken); err != nil {
			return fmt.Errorf("store refreshed AIOps Pulse read token: %w", err)
		}
		report.recordMutation("Secrets", "aiops_pulse_read_token", "credential refreshed", true)
		pulseRead, err = pulse.NewReadClient(pulse.ClientConfig{
			BaseURL: pulseBaseURL, APIToken: readToken,
			CAPEM: authority.IssuingCertPEM, ClientCertPEM: pulseReadCertificate.CertPEM, ClientKeyPEM: pulseReadCertificate.KeyPEM,
			ServerName: "monitor." + s.Network.Domain,
		})
		if err != nil {
			return fmt.Errorf("reconfigure AIOps Pulse read client: %w", err)
		}
		if _, err := pulseRead.StateSummary(ctx); err != nil {
			return fmt.Errorf("validate refreshed AIOps Pulse read token: %w", err)
		}
	}
	if created {
		report.recordMutation("Secrets", "aiops_pulse_read_token", "credential stored", true)
	}
	noteToken, created, err := loadOrCreatePulseToken(siteDir, ageIdentity, s, "aiops_pulse_note_token", func() (string, error) {
		return pulseAdmin.CreateIncidentNoteToken(ctx, "boetticher aiops notes")
	})
	if err != nil {
		return err
	}
	if created {
		report.recordMutation("Secrets", "aiops_pulse_note_token", "credential stored", true)
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
	return runTrackedAnsiblePhase(ctx, ansiblePlaybook, inventoryPath, append(variables, '\n'), "lab-aiops-01", ansible.PhaseHealth, report)
}

func selectedAIOpsModel(s model.Site) (model.BifrostModelConfig, error) {
	alias := s.ModuleConfig["aiops"].ModelAlias
	var selected model.BifrostModelConfig
	for _, candidate := range s.ModuleConfig["bifrost"].Models {
		if candidate.Alias != alias {
			continue
		}
		if selected.Alias != "" {
			return model.BifrostModelConfig{}, errors.New("AIOps model alias is ambiguous")
		}
		selected = candidate
	}
	if selected.Alias == "" {
		return model.BifrostModelConfig{}, errors.New("AIOps model alias is undeclared")
	}
	return selected, nil
}

func controllerMTLSClient(authority pki.Authority, certificate pki.ClientCertificate, forwardAddress string) (*http.Client, error) {
	identity, err := tls.X509KeyPair([]byte(certificate.ChainPEM), []byte(certificate.KeyPEM))
	if err != nil {
		return nil, fmt.Errorf("load controller AIOps canary identity: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(authority.RootCertPEM + authority.IssuingCertPEM)) {
		return nil, errors.New("platform CA contains no certificates")
	}
	forwardHost, forwardPort, err := net.SplitHostPort(forwardAddress)
	if err != nil || forwardHost != "127.0.0.1" || forwardPort == "" {
		return nil, errors.New("AI Router canary requires a loopback SSH forward")
	}
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, net.JoinHostPort(forwardHost, forwardPort))
		},
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{identity}}, DisableCompression: true, ResponseHeaderTimeout: 30 * time.Second,
	}
	return &http.Client{Transport: transport, Timeout: 60 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("AI Router redirects are forbidden") }}, nil
}

func loadOrCreateAIOpsSecret(siteDir, ageIdentity string, s model.Site, key string) (string, bool, error) {
	value, err := site.LoadPlatformSecret(siteDir, s, ageIdentity, key)
	if err == nil {
		return value, false, nil
	}
	if !errors.Is(err, site.ErrPlatformSecretMissing) {
		return "", false, fmt.Errorf("load encrypted %s: %w", key, err)
	}
	var data [32]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", false, fmt.Errorf("generate %s: %w", key, err)
	}
	value = base64.RawURLEncoding.EncodeToString(data[:])
	if err := site.StorePlatformSecret(siteDir, s, ageIdentity, key, value); err != nil {
		return "", false, fmt.Errorf("store encrypted %s: %w", key, err)
	}
	return value, true, nil
}

func loadOrCreatePulseToken(siteDir, ageIdentity string, s model.Site, key string, create func() (string, error)) (string, bool, error) {
	value, err := site.LoadPlatformSecret(siteDir, s, ageIdentity, key)
	if err == nil {
		return value, false, nil
	}
	if !errors.Is(err, site.ErrPlatformSecretMissing) {
		return "", false, fmt.Errorf("load encrypted %s: %w", key, err)
	}
	value, err = create()
	if err != nil {
		return "", false, err
	}
	if err := site.StorePlatformSecret(siteDir, s, ageIdentity, key, value); err != nil {
		return "", false, fmt.Errorf("store encrypted %s: %w", key, err)
	}
	return value, true, nil
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
		KnownHosts:    deploymentKnownHosts(siteDir),
		StrictHostKey: "yes",
		HostAlias:     hostAlias,
	}
}

type temporaryRootCleanup struct {
	s                 model.Site
	siteDir           string
	operatorPublicKey string
	host              bool
	guests            []proxmox.GuestPlan
	guestNames        map[string]struct{}
}

func newTemporaryRootCleanup(s model.Site, siteDir, operatorPublicKey string) *temporaryRootCleanup {
	return &temporaryRootCleanup{s: s, siteDir: siteDir, operatorPublicKey: operatorPublicKey, guestNames: make(map[string]struct{})}
}

func (c *temporaryRootCleanup) hostEstablished() {
	c.host = true
}

func (c *temporaryRootCleanup) guestEstablished(guest proxmox.GuestPlan) {
	if _, ok := c.guestNames[guest.Name]; ok {
		return
	}
	c.guestNames[guest.Name] = struct{}{}
	c.guests = append(c.guests, guest)
}

func (c *temporaryRootCleanup) revoke(ctx context.Context) error {
	if !c.host && len(c.guests) == 0 {
		return nil
	}
	return revokeTemporaryRootAccessForGuests(ctx, c.s, c.siteDir, c.guests, c.operatorPublicKey, c.host)
}

func revokeTemporaryRootAccessForGuests(ctx context.Context, s model.Site, siteDir string, guests []proxmox.GuestPlan, operatorPublicKey string, host bool) error {
	for _, guest := range guests {
		if guest.Owner == "" || guest.Address == "" {
			continue
		}
		runner := applianceSSHRunner(s, siteDir, guest.Name)
		if err := proxmox.RevokeTemporaryRootAccess(ctx, runner, guest.Address, "root", operatorPublicKey, false); err != nil {
			return fmt.Errorf("revoke root access on %s: %w", guest.Name, err)
		}
	}
	if host {
		hostRunner := proxmoxRootSSHRunner(s, siteDir)
		if err := proxmox.RevokeTemporaryRootAccess(ctx, hostRunner, s.BootstrapAddress, "root", operatorPublicKey, true); err != nil {
			return fmt.Errorf("revoke root access on %s: %w", model.LogicalProxmoxIdentity, err)
		}
	}
	return nil
}

func retainedGuestPlans(s model.Site) ([]proxmox.GuestPlan, error) {
	guests := make([]proxmox.GuestPlan, 0)
	for _, retained := range s.RetainedModules {
		artifact, err := artifacts.ArtifactFor(retained.Module)
		if err != nil {
			return nil, fmt.Errorf("resolve retained %s artifact identity: %w", retained.Module, err)
		}
		var kind proxmox.GuestKind
		switch artifact.Kind {
		case string(proxmox.KindQEMU):
			kind = proxmox.KindQEMU
		case string(proxmox.KindLXC):
			kind = proxmox.KindLXC
		default:
			return nil, fmt.Errorf("retained %s has unsupported artifact kind %q", retained.Module, artifact.Kind)
		}
		for _, component := range retained.Guests {
			guests = append(guests, proxmox.GuestPlan{
				VMID: component.VMID, Name: component.Name, Hostname: component.Hostname, Kind: kind,
				Zone: component.Zone, Address: component.Address, Owner: "boetticher/module/" + retained.Module,
			})
		}
	}
	return guests, nil
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
	if err := sshconfig.ValidateBootstrapAddress(s.BootstrapAddress); err != nil {
		return nil, site.ProxmoxCredentials{}, err
	}
	credentials, err := site.LoadProxmoxCredentials(siteDir, s, ageIdentity)
	if err != nil {
		return nil, site.ProxmoxCredentials{}, fmt.Errorf("load encrypted Proxmox API credentials: %w", err)
	}
	client, err := proxmox.NewClient(proxmox.Config{
		BaseURL: "https://" + s.BootstrapAddress + ":8006/api2/json", User: credentials.APIUser,
		TokenID: credentials.TokenID, TokenSecret: credentials.TokenSecret, CAFile: caFile, CAPEM: credentials.CAPEM, Insecure: insecure,
		SnippetRunner: proxmox.SSHRunner{
			IdentityFile:  operatorIdentityFile(s),
			ConfigFile:    filepath.Join(siteDir, "generated", "ssh", "boetticher.conf"),
			KnownHosts:    deploymentKnownHosts(siteDir),
			StrictHostKey: "yes", HostKeyAlias: model.LogicalProxmoxIdentity,
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
		KnownHosts:    deploymentKnownHosts(siteDir),
		StrictHostKey: "yes",
		HostAlias:     model.LogicalProxmoxIdentity,
	}
}

func proxmoxBastionSSHRunner(s model.Site, siteDir string) proxmox.SSHRunner {
	return proxmox.SSHRunner{
		IdentityFile:  operatorIdentityFile(s),
		ConfigFile:    filepath.Join(siteDir, "generated", "ssh", "boetticher.conf"),
		KnownHosts:    deploymentKnownHosts(siteDir),
		StrictHostKey: "yes",
		HostAlias:     "lab-bastion",
	}
}

func remoteEndpointResolver(ctx context.Context, runner proxmox.ArgsCommandRunner, address, user string) func(string) ([]net.IP, error) {
	return func(host string) ([]net.IP, error) {
		if strings.TrimSpace(host) != host || host == "" || strings.ContainsAny(host, " \t\r\n/") {
			return nil, errors.New("endpoint hostname is invalid")
		}
		output, err := runner.RunArgs(ctx, address, user, []string{"getent", "ahostsv4", host})
		if err != nil {
			return nil, err
		}
		seen := map[string]struct{}{}
		addresses := make([]net.IP, 0)
		for _, line := range strings.Split(string(output), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			ip := net.ParseIP(fields[0])
			if ip == nil || ip.To4() == nil {
				continue
			}
			ip = ip.To4()
			if _, ok := seen[ip.String()]; ok {
				continue
			}
			seen[ip.String()] = struct{}{}
			addresses = append(addresses, ip)
		}
		if len(addresses) == 0 {
			return nil, fmt.Errorf("remote resolver returned no IPv4 addresses for %s", host)
		}
		return addresses, nil
	}
}

func endpointLookupWithFallback(primary, fallback func(string) ([]net.IP, error)) func(string) ([]net.IP, error) {
	return func(host string) ([]net.IP, error) {
		addresses, primaryErr := primary(host)
		for _, address := range addresses {
			if address != nil && address.To4() != nil {
				return addresses, nil
			}
		}
		if fallback == nil {
			return nil, primaryErr
		}
		fallbackAddresses, fallbackErr := fallback(host)
		if fallbackErr != nil {
			if primaryErr != nil {
				return nil, fmt.Errorf("controller resolver: %v; Proxmox resolver: %w", primaryErr, fallbackErr)
			}
			return nil, fallbackErr
		}
		return fallbackAddresses, nil
	}
}

func deploymentKnownHosts(siteDir string) string {
	return filepath.Join(siteDir, "generated", "ssh", "known_hosts")
}

func retireReplacedHostKey(siteDir string, s model.Site, guest proxmox.GuestPlan) error {
	if guest.Hostname == "" {
		return fmt.Errorf("guest %s has no host-key identity", guest.Name)
	}
	return sshconfig.RemoveHostKey(deploymentKnownHosts(siteDir), guest.Hostname+"."+s.Network.Domain)
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
	trustedKey, err := sshconfig.ReadHostKey(deploymentKnownHosts(siteDir), model.LogicalProxmoxIdentity)
	if err != nil {
		return fmt.Errorf("Proxmox host key is not enrolled in the site trust file: %w", err)
	}
	if trustedKey != evidence.SSHHostKey {
		return errors.New("recorded Proxmox host key does not match the enrolled site trust key")
	}
	return nil
}

func runTrackedAnsible(ctx context.Context, playbook, inventory string, variables []byte, limit string, report *deploymentReport) error {
	return runTrackedAnsiblePhase(ctx, playbook, inventory, variables, limit, ansible.PhaseFull, report)
}

func runTrackedAnsiblePhase(ctx context.Context, playbook, inventory string, variables []byte, limit, phase string, report *deploymentReport) error {
	started := time.Now()
	var (
		result ansible.RunResult
		err    error
	)
	if limit == "" {
		result, err = ansible.RunWithMutationPhase(ctx, playbook, inventory, variables, phase)
	} else {
		result, err = ansible.RunLimitedWithMutationPhase(ctx, playbook, inventory, variables, limit, phase)
	}
	if result.Changed {
		target := limit
		if target == "" {
			target = "all managed targets"
		}
		if report != nil {
			report.recordMutation("Services", target, "configuration reconciled", true)
		}
	}
	if report != nil {
		report.recordAnsibleTaskTimings(phase, result.TaskTimings)
		report.recordAnsibleTaskBatches(phase, result.TaskBatchTimings)
		for _, timing := range result.TaskTimings {
			for _, marker := range timing.Markers {
				fmt.Fprintf(report.out, "      Observation: %s (%s)\n", marker, timing.Host)
			}
		}
		target := limit
		if target == "" {
			target = "all managed targets"
		}
		report.recordTiming(report.activePhaseID(), "ansible", target, started)
	}
	return err
}
