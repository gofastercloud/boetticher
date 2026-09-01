package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/artifacts"
	"github.com/gofastercloud/boetticher/internal/model"
	networkmodel "github.com/gofastercloud/boetticher/internal/network"
	"github.com/gofastercloud/boetticher/internal/proxmox"
	"github.com/gofastercloud/boetticher/internal/site"
	"github.com/gofastercloud/boetticher/internal/sshconfig"
	"github.com/gofastercloud/boetticher/internal/storage"
	"github.com/gofastercloud/boetticher/internal/telemetry"
)

func runBootstrapEndpoint(args []string, out io.Writer) error {
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
		fmt.Fprintln(out, "Bootstrap endpoint: FAIL not configured; use boetticher bootstrap-endpoint set ADDRESS")
	} else {
		fmt.Fprintf(out, "Bootstrap endpoint: %s\n", s.BootstrapAddress)
	}
	return nil
}

func runBootstrap(args []string, out io.Writer) (runErr error) {
	progress := newBootstrapReport(out, bootstrapPhaseCount)
	defer func() { runErr = progress.finalize(runErr) }()
	totalStarted := time.Now()
	defer func() { progress.emitTiming(out, "bootstrap_total", totalStarted) }()
	fs := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	recoveryConfirmed := fs.Bool("recovery-confirmed", false, "confirm an independent Age recovery copy exists")
	storageConfirmed := fs.Bool("storage-confirmed", false, "confirm initialization of the configured dedicated data disk")
	operatorKey := fs.String("operator-key", "", "operator SSH public key path")
	initialUser := fs.String("initial-user", "root", "initial SSH user on the fresh Proxmox host")
	knownHosts := fs.String("known-hosts", "", "SSH known-hosts file for bootstrap; defaults to the site trust file")
	proxmoxCA := fs.String("proxmox-ca", "", "Proxmox API CA PEM file")
	insecure := fs.Bool("insecure", false, "explicitly allow self-signed Proxmox API TLS during bootstrap")
	trunkInterface := fs.String("trunk-interface", "", "explicit physical trunk interface when discovery finds multiple candidates")
	dryRun := fs.Bool("dry-run", false, "render and validate the bootstrap plan without connecting")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dryRun {
		progress.total = 1
	}
	progress.start("validate", "Validate bootstrap request")
	if *knownHosts == "" {
		*knownHosts = deploymentKnownHosts(*siteDir)
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	progress.setTimingPath(filepath.Join(site.RuntimeDir(s), "bootstrap", progress.runID+".json"))
	plan, err := proxmox.PlanFromSite(s)
	if err != nil {
		return err
	}
	if s.BootstrapAddress == "" {
		return errors.New("bootstrap endpoint is not configured; use boetticher bootstrap-endpoint set ADDRESS first")
	}
	modelRevision, revisionErr := s.Revision()
	if revisionErr != nil {
		return fmt.Errorf("calculate model revision: %w", revisionErr)
	}
	progress.setIdentity(model.PlatformVersion, modelRevision)
	if !*dryRun {
		if err := site.ValidateAgeIdentity(*ageIdentity, s.SecretMetadata.AgeRecipient); err != nil {
			return fmt.Errorf("HOLD: Age identity is not usable for this site: %w", err)
		}
		if !*recoveryConfirmed {
			return errors.New("destructive bootstrap requires --recovery-confirmed after an independent Age recovery copy is secured")
		}
		if s.StorageProfile == "dedicated-data-disk" && !*storageConfirmed {
			return errors.New("dedicated-data-disk bootstrap requires --storage-confirmed after reviewing the configured stable device")
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
		progress.complete()
		fmt.Fprintf(out, "Bootstrap plan: PASS model %s\n", plan.ModelRevision)
		fmt.Fprintf(out, "  Proxmox endpoint: %s\n  Gateway mode: %s\n  Gateway upstream MAC: %s\n  Gateway image: %s\n", s.BootstrapAddress, s.Gateway.Mode, s.Gateway.Upstream.MAC, model.QualifiedGatewayImage)
		fmt.Fprintf(out, "  Storage: %s\n", s.StorageProfile)
		fmt.Fprintln(out, "  Trust transition: initial administrator → temporary root deployment SSH → scoped API token → durable labadmin")
		builder := artifacts.Builder()
		fmt.Fprintf(out, "  Artifact builder: temporary VMID %d (%s, %s)\n", builder.VMID, builder.Hostname, builder.Network)
		fmt.Fprintln(out, "  Artifact qualification: base, selected appliances, SBOM, Trivy, independent content SHA-256")
		fmt.Fprintln(out, "  Destructive actions: not applied (dry-run)")
		return nil
	}
	progress.complete()
	progress.start("discover", "Discover physical network")
	publicKey, err := readOperatorPublicKey(*operatorKey)
	if err != nil {
		return err
	}
	runner := proxmox.SSHRunner{KnownHosts: *knownHosts, StrictHostKey: "ask", HostKeyAlias: model.LogicalProxmoxIdentity}
	ctx := context.Background()
	ctx = telemetry.WithObserver(ctx, progress)
	sshDiscovery, err := proxmox.DiscoverPhysicalNetworkViaSSH(ctx, runner, s.BootstrapAddress, *initialUser, s.BootstrapAddress, s.PhysicalNetwork.Trunk.Name, *trunkInterface)
	if err != nil {
		return err
	}
	trustedKnownHosts := deploymentKnownHosts(*siteDir)
	progress.complete()
	progress.start("trust", "Establish host trust and scoped access")
	hostKey, err := enrollBootstrapHostKey(*knownHosts, trustedKnownHosts)
	if err != nil {
		return fmt.Errorf("HOLD: bootstrap did not establish an operator-verified Proxmox host key: %w", err)
	}
	runner = proxmox.SSHRunner{KnownHosts: trustedKnownHosts, StrictHostKey: "yes", HostKeyAlias: model.LogicalProxmoxIdentity}
	credentialsPath := filepath.Join(*siteDir, site.ProxmoxSecretsPath)
	credentialsExist, err := proxmoxCredentialsExist(credentialsPath)
	if err != nil {
		return fmt.Errorf("inspect existing Proxmox API credentials: %w", err)
	}
	var credentials site.ProxmoxCredentials
	if credentialsExist {
		credentials, err = site.LoadProxmoxCredentials(*siteDir, s, *ageIdentity)
		if err != nil {
			return fmt.Errorf("load existing Proxmox API credentials: %w", err)
		}
		if credentials.APIUser != "labadmin@pve" || credentials.TokenID != "boetticher" {
			return fmt.Errorf("HOLD: encrypted Proxmox credentials identify %s!%s, expected labadmin@pve!boetticher", credentials.APIUser, credentials.TokenID)
		}
	} else if err := proxmox.CheckScopedCredentialAvailability(ctx, runner, s.BootstrapAddress, *initialUser, "labadmin@pve", "boetticher", "BoetticherProvisioner"); err != nil {
		return err
	}
	proxmoxCAPEM := credentials.CAPEM
	if *proxmoxCA != "" {
		caData, readErr := os.ReadFile(*proxmoxCA)
		if readErr != nil {
			return fmt.Errorf("read Proxmox API CA file: %w", readErr)
		}
		proxmoxCAPEM = string(caData)
	}
	if err := proxmox.InstallOperatorKey(ctx, runner, s.BootstrapAddress, *initialUser, publicKey); err != nil {
		return fmt.Errorf("install operator SSH key: %w", err)
	}
	if s.StorageProfile == "dedicated-data-disk" {
		if err := storage.Initialize(ctx, runner, s.BootstrapAddress, *initialUser, s.StorageDevice, *storageConfirmed); err != nil {
			return err
		}
	}
	allowedDestinations := jumpDestinations(s)
	if err := proxmox.ConfigureIdentities(ctx, runner, s.BootstrapAddress, *initialUser, publicKey, allowedDestinations); err != nil {
		return fmt.Errorf("configure Proxmox administrative and bastion identities: %w", err)
	}
	trustClient, err := proxmox.NewClient(proxmox.Config{
		BaseURL: "https://" + s.BootstrapAddress + ":8006/api2/json", CAFile: *proxmoxCA, CAPEM: proxmoxCAPEM, Insecure: *insecure,
	})
	if err != nil {
		return fmt.Errorf("prepare Proxmox API trust before credential creation: %w", err)
	}
	if err := trustClient.CheckTLS(ctx); err != nil {
		return fmt.Errorf("verify Proxmox API TLS before credential creation: %w", err)
	}
	if credentialsExist {
		if proxmoxCAPEM != "" && credentials.CAPEM != proxmoxCAPEM {
			credentials.CAPEM = proxmoxCAPEM
			if err := site.StoreProxmoxCredentials(*siteDir, s, *ageIdentity, credentials); err != nil {
				return fmt.Errorf("store Proxmox API CA in SOPS: %w", err)
			}
			fmt.Fprintln(out, "Proxmox API CA in SOPS: PASS (stored)")
		}
		if err := proxmox.EnsureScopedCredentialACL(ctx, runner, s.BootstrapAddress, *initialUser, credentials.APIUser, credentials.TokenID, "BoetticherProvisioner"); err != nil {
			return fmt.Errorf("reconcile scoped Proxmox API credentials: %w", err)
		}
		fmt.Fprintln(out, "Existing encrypted Proxmox API credentials: PASS (reuse)")
	} else {
		tokenSecret, createErr := proxmox.CreateScopedCredentialsWithRole(ctx, runner, s.BootstrapAddress, *initialUser, "labadmin@pve", "boetticher", "BoetticherProvisioner")
		if createErr != nil {
			return fmt.Errorf("create scoped Proxmox API credentials: %w", createErr)
		}
		credentials = site.ProxmoxCredentials{APIUser: "labadmin@pve", TokenID: "boetticher", TokenSecret: tokenSecret, CAPEM: proxmoxCAPEM}
		if err := site.StoreProxmoxCredentials(*siteDir, s, *ageIdentity, credentials); err != nil {
			return fmt.Errorf("store Proxmox credentials and API CA in SOPS: %w", err)
		}
		if proxmoxCAPEM != "" {
			fmt.Fprintln(out, "Proxmox API CA in SOPS: PASS (stored)")
		}
	}
	client, err := proxmox.NewClient(proxmox.Config{
		BaseURL: "https://" + s.BootstrapAddress + ":8006/api2/json", User: credentials.APIUser,
		TokenID: credentials.TokenID, TokenSecret: credentials.TokenSecret, CAFile: *proxmoxCA, CAPEM: proxmoxCAPEM, Insecure: *insecure,
		SnippetRunner: runner, SnippetAddress: s.BootstrapAddress, SnippetUser: *initialUser,
	})
	if err != nil {
		return err
	}
	version, err := client.Version(ctx)
	if err != nil {
		return fmt.Errorf("authenticate to Proxmox with scoped identity: %w", err)
	}
	apiNode, err := client.SingleNode(ctx)
	if err != nil {
		return err
	}
	if apiNode != sshDiscovery.Node {
		return fmt.Errorf("HOLD: Proxmox node identity changed between SSH and API discovery; SSH observed %q, API observed %q", sshDiscovery.Node, apiNode)
	}
	plan.Node = apiNode
	progress.complete()
	progress.start("platform", "Reconcile Proxmox network and storage")
	discovery, err := proxmox.DiscoverPhysicalNetworkWithSelection(ctx, client, apiNode, s.BootstrapAddress, s.PhysicalNetwork.Trunk.Name, *trunkInterface)
	virtualOnlyRequested := s.PhysicalNetwork.Mode == model.ModeVirtualOnly && s.PhysicalNetwork.Trunk.Name == "" && *trunkInterface == ""
	discovery = honorRequestedPhysicalMode(discovery, s.PhysicalNetwork.Mode, s.PhysicalNetwork.Trunk.Name, *trunkInterface)
	printPhysicalDiscovery(out, discovery)
	if discovery.Mode == networkmodel.ModeSelectionNeeded {
		return errors.New("multiple eligible trunk interfaces require --trunk-interface selection before bootstrap can mutate networking")
	}
	if s.Gateway.Mode == model.GatewayModeExternal && discovery.Trunk == nil {
		return errors.New("external gateway mode requires a distinct physical vmbr1 trunk interface")
	}
	if err := proxmox.EnsureVirtualBridge(ctx, client, apiNode); err != nil {
		return err
	}
	if err := client.ReloadNodeNetwork(ctx, apiNode); err != nil {
		return err
	}
	if err := proxmox.ConfigureManagementNetwork(ctx, runner, s.BootstrapAddress, *initialUser); err != nil {
		return err
	}
	localContent, err := storage.LocalStorageContent(s.StorageProfile)
	if err != nil {
		return err
	}
	if err := client.EnsureDirectoryStorageContent(ctx, "local", "/var/lib/vz", localContent); err != nil {
		return fmt.Errorf("ensure local Proxmox storage: %w", err)
	}
	trunkChanged := false
	if discovery.Trunk != nil && discovery.Trunk.Bridge != "vmbr1" {
		if err := proxmox.AttachTrunk(ctx, client, apiNode, discovery.Trunk.Name, s.BootstrapAddress); err != nil {
			return err
		}
		trunkChanged = true
	}
	var postInterfaces []proxmox.NetworkInterface
	if err := client.NodeNetwork(ctx, apiNode, &postInterfaces); err != nil {
		if trunkChanged {
			return rollbackTrunkChange(ctx, client, apiNode, discovery.Trunk.Name, s.BootstrapAddress, "HOLD: bootstrap network mutation could not be re-read", err)
		}
		return fmt.Errorf("HOLD: bootstrap network state could not be re-read: %w", err)
	}
	configuredTrunk := ""
	if discovery.Trunk != nil {
		configuredTrunk = discovery.Trunk.Name
	}
	postDiscovery := discovery
	if !virtualOnlyRequested {
		postDiscovery, err = proxmox.AnalyzePhysicalNetwork(postInterfaces, s.BootstrapAddress, configuredTrunk)
	}
	if err != nil {
		if trunkChanged {
			return rollbackTrunkChange(ctx, client, apiNode, discovery.Trunk.Name, s.BootstrapAddress, "HOLD: bootstrap network mutation failed physical validation", err)
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
			return rollbackTrunkChange(ctx, client, apiNode, discovery.Trunk.Name, s.BootstrapAddress, "HOLD: bootstrap network binding validation failed", err)
		}
		return fmt.Errorf("HOLD: bootstrap network binding validation failed: %w", err)
	}
	if err := site.Save(*siteDir, s); err != nil {
		if trunkChanged {
			return rollbackTrunkChange(ctx, client, apiNode, discovery.Trunk.Name, s.BootstrapAddress, "HOLD: bootstrap network binding could not be persisted", err)
		}
		return fmt.Errorf("HOLD: bootstrap network binding could not be persisted: %w", err)
	}
	plan, err = proxmox.PlanFromSite(s)
	if err != nil {
		return fmt.Errorf("HOLD: recompute platform plan after physical binding: %w", err)
	}
	plan.Node = apiNode
	progress.complete()
	progress.start("artifacts", "Build and qualify appliance artifacts")
	if err := buildDefaultArtifacts(ctx, client, plan, *siteDir, publicKey, *knownHosts, model.ExpandUserPath(s.SSHIdentityFile), runner, runner, s.BootstrapAddress, *initialUser, out, progress); err != nil {
		return err
	}
	plan, err = proxmox.ResolveQualifiedArtifacts(*siteDir, plan, true)
	if err != nil {
		return err
	}
	progress.complete()
	progress.start("persist", "Persist bootstrap state")
	if err := writeModelProjections(*siteDir, s); err != nil {
		return fmt.Errorf("HOLD: bootstrap network binding was persisted but projections could not be regenerated: %w", err)
	}
	if err := writePhysicalDiscovery(*siteDir, s, postDiscovery); err != nil {
		return fmt.Errorf("HOLD: bootstrap network binding was persisted but physical evidence could not be written: %w", err)
	}
	if err := rebuildPortal(*siteDir, s); err != nil {
		return fmt.Errorf("HOLD: bootstrap network binding was persisted but portal could not be regenerated: %w", err)
	}
	if err := site.Save(*siteDir, s); err != nil {
		return fmt.Errorf("HOLD: bootstrap completed network mutation but physical binding could not be persisted: %w", err)
	}
	plan, err = proxmox.PlanFromSite(s)
	if err != nil {
		return err
	}
	plan.Node = apiNode
	if err := writeProjection(filepath.Join(*siteDir, "generated", "bootstrap.json"), struct {
		ModelRevision     string `json:"model_revision"`
		ProxmoxVersion    string `json:"proxmox_version"`
		BootstrapAddress  string `json:"bootstrap_address"`
		SSHHostKey        string `json:"ssh_host_key"`
		OperatorPublicKey string `json:"operator_public_key"`
		GatewayVMID       int    `json:"gateway_vmid,omitempty"`
		Status            string `json:"status"`
	}{plan.ModelRevision, version, s.BootstrapAddress, hostKey, publicKey, func() int {
		if s.Gateway.Mode == model.GatewayModeManaged {
			return model.ProxmoxVMID
		}
		return 0
	}(), "proxmox-trust-transition-complete"}); err != nil {
		return err
	}
	progress.complete()
	fmt.Fprintf(out, "Proxmox bootstrap: PASS authenticated with scoped identity on %s\n", version)
	if s.Gateway.Mode == model.GatewayModeManaged {
		fmt.Fprintln(out, "Managed gateway VM: deferred to boetticher deploy")
		fmt.Fprintf(out, "Managed gateway upstream MAC: %s (create the matching upstream DHCP reservation)\n", s.Gateway.Upstream.MAC)
	} else {
		fmt.Fprintln(out, "External gateway: PASS physical VLAN trunk recorded; appliance remains operator-managed")
	}
	fmt.Fprintln(out, "Initial root/bootstrap authentication: no longer required for routine boetticher access")
	return nil
}

func enrollBootstrapHostKey(sourceKnownHosts, trustedKnownHosts string) (string, error) {
	operatorVerifiedKey, err := sshconfig.ReadHostKey(sourceKnownHosts, model.LogicalProxmoxIdentity)
	if err != nil {
		return "", fmt.Errorf("read operator-known Proxmox host key from %s: %w", sourceKnownHosts, err)
	}
	if err := sshconfig.AddKnownHostKey(trustedKnownHosts, model.LogicalProxmoxIdentity, operatorVerifiedKey); err != nil {
		return "", fmt.Errorf("enroll Proxmox host key: %w", err)
	}
	hostKey, err := sshconfig.ReadHostKey(trustedKnownHosts, model.LogicalProxmoxIdentity)
	if err != nil {
		return "", fmt.Errorf("read enrolled Proxmox SSH host identity: %w", err)
	}
	return hostKey, nil
}

func proxmoxCredentialsExist(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func emitTiming(out io.Writer, stage string, started time.Time) {
	if out == nil || stage == "" || started.IsZero() {
		return
	}
	fmt.Fprintf(out, "timing stage=%s duration_ms=%d\n", stage, time.Since(started).Milliseconds())
}

func builderArtifactReturnCommand(compression string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(compression)) {
	case "", "gzip":
		return "tar -czf - -C /home/labadmin/build generated/artifacts", nil
	case "plain", "none":
		return "tar -cf - -C /home/labadmin/build generated/artifacts", nil
	default:
		return "", fmt.Errorf("unsupported builder artifact transport compression %q", compression)
	}
}

// honorRequestedPhysicalMode keeps a fresh virtual-only site virtual-only even
// when hardware discovery finds one eligible spare interface. A physical
// trunk enters the model only through an explicit selection or an already
// persisted boetticher trunk binding.
func honorRequestedPhysicalMode(discovery networkmodel.Discovery, desiredMode, configuredTrunk, explicitTrunk string) networkmodel.Discovery {
	if desiredMode == model.ModeVirtualOnly && configuredTrunk == "" && explicitTrunk == "" {
		discovery.Mode = networkmodel.ModeVirtualOnly
		discovery.Trunk = nil
		discovery.Explanation = "site explicitly requests virtual-only networking; eligible spare interfaces remain unclaimed"
		discovery.Status = "PASS"
	}
	return discovery
}

func buildDefaultArtifacts(ctx context.Context, client *proxmox.Client, plan proxmox.Plan, siteDir, publicKey, _ string, identityFile string, hostRunner proxmox.CommandRunner, hostArgsRunner proxmox.ArgsCommandRunner, hostAddress, hostUser string, out io.Writer, progress *bootstrapReport) (returnErr error) {
	cacheStarted := time.Now()
	base, err := artifacts.ArtifactFor("base")
	if err != nil {
		return err
	}
	if _, _, err := artifacts.ResolveArtifactEvidence(siteDir, base); err == nil {
		if _, err := proxmox.ResolveQualifiedArtifacts(siteDir, plan, true); err == nil {
			progress.emitTiming(out, "artifact_cache_hit", cacheStarted)
			return nil
		}
	}
	progress.emitTiming(out, "artifact_cache_check", cacheStarted)
	if client == nil {
		return errors.New("Proxmox client is required for appliance construction")
	}
	cacheVolume, err := proxmox.EnsureBuilderCacheVolume(ctx, client, plan.Node, hostArgsRunner, hostAddress, hostUser)
	if err != nil {
		return fmt.Errorf("prepare persistent builder cache: %w", err)
	}
	plan.BuilderCacheVolume = cacheVolume
	transportCompression := strings.ToLower(strings.TrimSpace(os.Getenv("BOETTICHER_BUILDER_TRANSPORT_COMPRESSION")))
	if transportCompression == "" {
		transportCompression = "gzip"
	}
	returnCommand, err := builderArtifactReturnCommand(transportCompression)
	if err != nil {
		return err
	}
	builderKnownHosts, err := createBuilderKnownHosts()
	if err != nil {
		return fmt.Errorf("create temporary builder known_hosts: %w", err)
	}
	defer func() {
		if cleanupErr := os.Remove(builderKnownHosts); cleanupErr != nil && !errors.Is(cleanupErr, os.ErrNotExist) {
			if returnErr == nil {
				returnErr = fmt.Errorf("remove temporary builder known_hosts: %w", cleanupErr)
			} else {
				returnErr = fmt.Errorf("%w (temporary builder known_hosts cleanup: %v)", returnErr, cleanupErr)
			}
		}
	}()
	provisionStarted := time.Now()
	builderCreated, err := proxmox.EnsureBuilderVM(ctx, client, plan, publicKey)
	progress.emitTiming(out, "builder_vm_provisioning", provisionStarted)
	builderAddress := ""
	builderRunner := proxmox.SSHRunner{KnownHosts: builderKnownHosts, StrictHostKey: "yes", IdentityFile: identityFile}
	builderSSHUser := "root"
	buildSucceeded := false
	builderOutput := ""
	if builderCreated {
		defer func() {
			var cleanupErr error
			if !buildSucceeded {
				if builderAddress != "" {
					if err := persistBuilderDiagnosticsWithOutput(ctx, builderRunner, builderAddress, builderSSHUser, siteDir, builderOutput); err != nil {
						cleanupErr = errors.Join(cleanupErr, err)
					}
				} else if err := persistBuilderUnavailableDiagnostics(siteDir, returnErr); err != nil {
					cleanupErr = errors.Join(cleanupErr, err)
				}
			}
			if err := proxmox.DestroyBuilderVM(ctx, client, plan.Node); err != nil {
				cleanupErr = errors.Join(cleanupErr, err)
			}
			if cleanupErr != nil {
				if returnErr == nil {
					returnErr = cleanupErr
				} else {
					returnErr = fmt.Errorf("%w (temporary builder cleanup: %v)", returnErr, cleanupErr)
				}
			}
		}()
	}
	if err != nil {
		return err
	}
	readinessStarted := time.Now()
	readinessFinished := false
	defer func() {
		if !readinessFinished {
			progress.emitTiming(out, "builder_cloud_init_readiness", readinessStarted)
		}
	}()
	if err := client.StartVM(ctx, plan.Node, model.BuilderVMID); err != nil {
		return fmt.Errorf("start temporary appliance builder: %w", err)
	}
	builderAddress, err = proxmox.WaitForQEMUIPv4(ctx, client, plan.Node, model.BuilderVMID, 60, 5*time.Second)
	if err != nil {
		return err
	}
	builderHostKey, err := waitForBuilderHostKey(ctx, hostRunner, hostAddress, hostUser, model.BuilderVMID, 60, 5*time.Second)
	if err != nil {
		return fmt.Errorf("HOLD: temporary appliance builder host-key enrollment failed: %w", err)
	}
	if err := sshconfig.AddHostKey(builderKnownHosts, builderAddress, builderHostKey); err != nil {
		return fmt.Errorf("enroll temporary appliance builder host key: %w", err)
	}
	if err := proxmox.WaitForSSH(ctx, builderRunner, builderAddress, builderSSHUser, 60, 5*time.Second); err != nil {
		return fmt.Errorf("HOLD: temporary appliance builder SSH is not ready: %w", err)
	}
	if err := proxmox.WaitForCommand(ctx, builderRunner, builderAddress, builderSSHUser, "test -f /run/boetticher-builder-ready", 60, 5*time.Second); err != nil {
		return fmt.Errorf("HOLD: temporary appliance builder cloud-init is not ready: %w", err)
	}
	builder := artifacts.Builder()
	if err := proxmox.CheckBuilderCapacity(ctx, builderRunner, builderAddress, builderSSHUser, builder.MinimumFreeGiB); err != nil {
		return err
	}
	progress.emitTiming(out, "builder_cloud_init_readiness", readinessStarted)
	readinessFinished = true
	sourceRoot, sourceErr := applianceBuildSourceRoot()
	sourceStarted := time.Now()
	var archive []byte
	if sourceErr == nil {
		archive, err = artifacts.BuildSourceArchive(sourceRoot)
	} else {
		archive, err = artifacts.BuildEmbeddedSourceArchive()
	}
	if err != nil {
		return fmt.Errorf("prepare public appliance build inputs: %w", err)
	}
	if _, err := builderRunner.RunWithStdin(ctx, builderAddress, builderSSHUser, "set -eu; install -d -m 0755 -o labadmin -g labadmin /home/labadmin/build; tar -xzf - -C /home/labadmin/build", bytes.NewReader(archive)); err != nil {
		return fmt.Errorf("transfer public appliance build definitions: %w", err)
	}
	progress.emitTiming(out, "builder_source_transfer", sourceStarted)
	var buildOutputBuffer boundedBuilderOutput
	buildStarted := time.Now()
	if err := builderRunner.RunStream(ctx, builderAddress, builderSSHUser, "/usr/local/sbin/boetticher-build", &buildOutputBuffer); err != nil {
		builderOutput = buildOutputBuffer.String()
		progress.emitTiming(out, "builder_build_and_qualification", buildStarted)
		return fmt.Errorf("qualify default appliance artifacts on temporary builder: %w", err)
	}
	progress.emitTiming(out, "builder_build_and_qualification", buildStarted)
	archiveFile, err := os.CreateTemp("", "boetticher-builder-artifacts-*.tar.gz")
	if err != nil {
		return fmt.Errorf("create temporary artifact archive: %w", err)
	}
	archivePath := archiveFile.Name()
	defer os.Remove(archivePath)
	if err := archiveFile.Chmod(0o600); err != nil {
		_ = archiveFile.Close()
		return fmt.Errorf("protect temporary artifact archive: %w", err)
	}
	returnStarted := time.Now()
	boundedArchive := &boundedBuilderArchive{writer: archiveFile, limit: maxBuilderArchiveBytes}
	if err := builderRunner.RunStream(ctx, builderAddress, builderSSHUser, returnCommand, boundedArchive); err != nil {
		_ = archiveFile.Close()
		return fmt.Errorf("retrieve qualified appliance evidence: %w", err)
	}
	if err := archiveFile.Close(); err != nil {
		return fmt.Errorf("close qualified appliance evidence: %w", err)
	}
	progress.emitTiming(out, "builder_artifact_return_transfer", returnStarted)
	archiveInfo, err := os.Stat(archivePath)
	if err != nil {
		return fmt.Errorf("stat qualified appliance evidence: %w", err)
	}
	fmt.Fprintf(out, "measurement stage=builder_artifact_return transport=%s bytes=%d\n", transportCompression, archiveInfo.Size())
	extractionStarted := time.Now()
	if err := artifacts.ExtractBuildArchiveFile(archivePath, siteDir); err != nil {
		return fmt.Errorf("extract qualified appliance evidence: %w", err)
	}
	if err := artifacts.RebindEvidencePaths(siteDir); err != nil {
		return fmt.Errorf("bind qualified evidence to controller artifact bytes: %w", err)
	}
	progress.emitTiming(out, "builder_artifact_return_extraction", extractionStarted)
	buildSucceeded = true
	return nil
}

func waitForBuilderHostKey(ctx context.Context, runner proxmox.CommandRunner, address, user string, vmid, attempts int, interval time.Duration) (string, error) {
	if runner == nil {
		return "", errors.New("authenticated Proxmox host runner is required")
	}
	if address == "" || user == "" || vmid <= 0 || attempts < 1 {
		return "", errors.New("builder host-key enrollment identity is invalid")
	}
	if interval <= 0 {
		interval = time.Second
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return "", fmt.Errorf("builder host-key enrollment cancelled: %w", err)
		}
		key, err := proxmox.ReadBuilderHostKey(ctx, runner, address, user, vmid)
		if err == nil {
			return key, nil
		}
		lastErr = err
		if attempt+1 < attempts {
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return "", fmt.Errorf("builder host-key enrollment cancelled: %w", ctx.Err())
			case <-timer.C:
			}
		}
	}
	return "", fmt.Errorf("builder host key was not available after %d attempts: %w", attempts, lastErr)
}

func createBuilderKnownHosts() (string, error) {
	file, err := os.CreateTemp("", "boetticher-builder-known-hosts-")
	if err != nil {
		return "", err
	}
	name := file.Name()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(name)
		return "", err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	return name, nil
}

const maxBuilderDiagnosticOutput = 32 << 10
const maxBuilderArchiveBytes int64 = 8 << 30

func persistBuilderDiagnostics(ctx context.Context, runner proxmox.CommandRunner, address, user, siteDir string) error {
	return persistBuilderDiagnosticsWithOutput(ctx, runner, address, user, siteDir, "")
}

func persistBuilderDiagnosticsWithOutput(ctx context.Context, runner proxmox.CommandRunner, address, user, siteDir, buildOutput string) error {
	if runner == nil || address == "" || user == "" || siteDir == "" {
		return errors.New("builder diagnostics require an authenticated runner and destination")
	}
	commands := []struct {
		label   string
		command string
	}{
		{label: "cloud-init", command: "cloud-init status --long"},
		{label: "cloud-final", command: "journalctl -u cloud-final --no-pager --lines=100"},
		{label: "boetticher-build", command: "tail -n 200 /var/log/boetticher-build.log"},
		{label: "disk", command: "df -h"},
		{label: "memory", command: "free -h"},
		{label: "go", command: "/usr/local/go/bin/go version"},
		{label: "trivy", command: "trivy --version"},
		{label: "mmdebstrap", command: "mmdebstrap --version"},
		{label: "kernel", command: "uname -a"},
	}
	var report strings.Builder
	for _, item := range commands {
		fmt.Fprintf(&report, "[%s]\n", item.label)
		output, err := runner.Run(ctx, address, user, item.command)
		if len(output) > maxBuilderDiagnosticOutput {
			output = append(output[:maxBuilderDiagnosticOutput], []byte("\n[output truncated]\n")...)
		}
		report.Write(output)
		if err != nil {
			fmt.Fprintf(&report, "command error: %v\n", err)
		}
		report.WriteByte('\n')
	}
	if buildOutput != "" {
		fmt.Fprintf(&report, "[builder-command-output]\n%s\n", buildOutput)
	}
	return writeBuilderDiagnostics(siteDir, report.String())
}

type boundedBuilderOutput struct {
	buffer bytes.Buffer
}

func (b *boundedBuilderOutput) Write(data []byte) (int, error) {
	remaining := maxBuilderDiagnosticOutput - b.buffer.Len()
	if remaining > 0 {
		if len(data) > remaining {
			_, _ = b.buffer.Write(data[:remaining])
		} else {
			_, _ = b.buffer.Write(data)
		}
	}
	return len(data), nil
}

type boundedBuilderArchive struct {
	writer  io.Writer
	limit   int64
	written int64
}

func (b *boundedBuilderArchive) Write(data []byte) (int, error) {
	if int64(len(data)) > b.limit-b.written {
		return 0, fmt.Errorf("builder artifact archive exceeds maximum size of %d bytes", b.limit)
	}
	written, err := b.writer.Write(data)
	b.written += int64(written)
	return written, err
}

func (b *boundedBuilderOutput) String() string { return b.buffer.String() }

func persistBuilderUnavailableDiagnostics(siteDir string, cause error) error {
	if siteDir == "" {
		return errors.New("builder diagnostics require a destination")
	}
	var report strings.Builder
	report.WriteString("remote builder diagnostics unavailable before a guest address was observed\n")
	if cause != nil {
		fmt.Fprintf(&report, "builder lifecycle error: %v\n", cause)
	}
	return writeBuilderDiagnostics(siteDir, report.String())
}

func writeBuilderDiagnostics(siteDir, content string) error {
	directory := filepath.Join(siteDir, "generated", "runtime")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create builder diagnostics directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".builder-failure-")
	if err != nil {
		return fmt.Errorf("create builder diagnostics file: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.WriteString(content); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write builder diagnostics: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close builder diagnostics: %w", err)
	}
	destination := filepath.Join(directory, "builder-failure.txt")
	if err := os.Rename(temporaryName, destination); err != nil {
		return fmt.Errorf("publish builder diagnostics: %w", err)
	}
	return nil
}

func applianceBuildSourceRoot() (string, error) {
	candidates := make([]string, 0, 3)
	if workingDirectory, err := os.Getwd(); err == nil {
		candidates = append(candidates, workingDirectory)
	}
	if executable, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Dir(executable))
	}
	if _, file, _, ok := runtime.Caller(0); ok {
		candidates = append(candidates, filepath.Dir(file))
	}
	for _, candidate := range candidates {
		for current := filepath.Clean(candidate); current != filepath.Dir(current); current = filepath.Dir(current) {
			if buildSourceRoot(current) {
				return current, nil
			}
		}
	}
	return "", errors.New("HOLD: public appliance build definitions are unavailable; run the release CLI from its build bundle or a boetticher source checkout")
}

func buildSourceRoot(root string) bool {
	for _, relative := range artifacts.PublicBuildInputs {
		info, err := os.Stat(filepath.Join(root, relative))
		if err != nil || (!info.IsDir() && !info.Mode().IsRegular()) {
			return false
		}
	}
	return true
}
