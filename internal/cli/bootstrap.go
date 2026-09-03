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

// runEnroll is the normal first-host enrollment entry point. It establishes
// durable host trust and scoped access; appliance deployment remains a
// separate signed-bundle operation.
func runEnroll(args []string, out io.Writer) error {
	return runEnrollOperation(args, out)
}

func runRecovery(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher recover host|storage|guest ...")
	}
	switch args[0] {
	case "host":
		return runEnrollOperation(args[1:], out)
	case "storage":
		return runStorage(args[1:], out)
	default:
		return fmt.Errorf("recovery target %q is not implemented in 0.5.1", args[0])
	}
}

func runEnrollOperation(args []string, out io.Writer) (runErr error) {
	progress := newBootstrapReport(out, bootstrapPhaseCount)
	defer func() { runErr = progress.finalize(runErr) }()
	totalStarted := time.Now()
	defer func() { progress.emitTiming(out, "enroll_total", totalStarted) }()
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	recoveryConfirmed := fs.Bool("recovery-confirmed", false, "confirm an independent Age recovery copy exists")
	storageConfirmed := fs.Bool("storage-confirmed", false, "confirm initialization of the configured dedicated data disk")
	replaceScopedCredentials := fs.Bool("replace-scoped-credentials", false, "replace the exact stale Boetticher Proxmox API token when its encrypted value is unavailable")
	operatorKey := fs.String("operator-key", "", "operator SSH public key path")
	bootstrapAddress := fs.String("bootstrap-address", "", "fresh Proxmox HOME-side IPv4 address")
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
	progress.start("validate", "Validate enrollment request")
	if *knownHosts == "" {
		*knownHosts = deploymentKnownHosts(*siteDir)
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	if *bootstrapAddress != "" {
		if err := sshconfig.ValidateBootstrapAddress(*bootstrapAddress); err != nil {
			return err
		}
		s.BootstrapAddress = net.ParseIP(*bootstrapAddress).To4().String()
	}
	progress.setTimingPath(filepath.Join(site.RuntimeDir(s), "enroll", progress.runID+".json"))
	plan, err := proxmox.PlanFromSite(s)
	if err != nil {
		return err
	}
	if s.BootstrapAddress == "" {
		return errors.New("bootstrap endpoint is not configured; pass --bootstrap-address ADDRESS on the first enroll")
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
			return errors.New("destructive enrollment requires --recovery-confirmed after an independent Age recovery copy is secured")
		}
		if s.StorageProfile == "dedicated-data-disk" && !*storageConfirmed {
			return errors.New("dedicated-data-disk enrollment requires --storage-confirmed after reviewing the configured stable device")
		}
	}
	if *operatorKey == "" {
		*operatorKey = defaultOperatorPublicKey()
	}
	if s.SSHIdentityFile == "" {
		if identity := inferredPrivateIdentity(*operatorKey); identity != "" {
			s.SSHIdentityFile = identity
		}
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
		fmt.Fprintf(out, "Enrollment plan: PASS model %s\n", plan.ModelRevision)
		fmt.Fprintf(out, "  Proxmox endpoint: %s\n  Gateway mode: %s\n  Gateway upstream MAC: %s\n  Gateway image: %s\n", s.BootstrapAddress, s.Gateway.Mode, s.Gateway.Upstream.MAC, model.QualifiedGatewayImage)
		fmt.Fprintf(out, "  Storage: %s\n", s.StorageProfile)
		fmt.Fprintln(out, "  Trust transition: initial administrator → temporary root deployment SSH → scoped API token → durable labadmin")
		fmt.Fprintln(out, "  Release source: authenticated offline bundle (no in-lab image builder)")
		fmt.Fprintln(out, "  Destructive actions: not applied (dry-run)")
		return nil
	}
	progress.complete()
	progress.start("discover", "Discover physical network")
	publicKey, err := readOperatorPublicKey(*operatorKey)
	if err != nil {
		return err
	}
	runner := proxmox.SSHRunner{KnownHosts: *knownHosts, StrictHostKey: "ask", HostKeyAlias: model.LogicalProxmoxIdentity, IdentityFile: operatorIdentityFile(s)}
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
		return fmt.Errorf("HOLD: enrollment did not establish an operator-verified Proxmox host key: %w", err)
	}
	runner = proxmox.SSHRunner{KnownHosts: trustedKnownHosts, StrictHostKey: "yes", HostKeyAlias: model.LogicalProxmoxIdentity, IdentityFile: operatorIdentityFile(s)}
	credentialsPath := filepath.Join(*siteDir, site.ProxmoxSecretsPath)
	credentialsExist, err := proxmoxCredentialsExist(credentialsPath)
	if err != nil {
		return fmt.Errorf("inspect existing Proxmox API credentials: %w", err)
	}
	var credentials site.ProxmoxCredentials
	if credentialsExist {
		if *replaceScopedCredentials {
			return errors.New("--replace-scoped-credentials is only valid when this site has no encrypted Proxmox credentials")
		}
		credentials, err = site.LoadProxmoxCredentials(*siteDir, s, *ageIdentity)
		if err != nil {
			return fmt.Errorf("load existing Proxmox API credentials: %w", err)
		}
		if credentials.APIUser != "labadmin@pve" || credentials.TokenID != "boetticher" {
			return fmt.Errorf("HOLD: encrypted Proxmox credentials identify %s!%s, expected labadmin@pve!boetticher", credentials.APIUser, credentials.TokenID)
		}
	} else {
		if *replaceScopedCredentials {
			removed, removeErr := proxmox.RemoveExactScopedCredentialToken(ctx, runner, s.BootstrapAddress, *initialUser, "labadmin@pve", "boetticher", "BoetticherProvisioner")
			if removeErr != nil {
				return removeErr
			}
			if removed {
				fmt.Fprintln(out, "Stale Boetticher scoped API token: PASS removed exact owned token")
			} else {
				fmt.Fprintln(out, "Stale Boetticher scoped API token: PASS no matching token present")
			}
		}
		if err := proxmox.CheckScopedCredentialAvailability(ctx, runner, s.BootstrapAddress, *initialUser, "labadmin@pve", "boetticher", "BoetticherProvisioner"); err != nil {
			return err
		}
	}
	proxmoxCAPEM := credentials.CAPEM
	if *proxmoxCA != "" {
		caData, readErr := os.ReadFile(*proxmoxCA)
		if readErr != nil {
			return fmt.Errorf("read Proxmox API CA file: %w", readErr)
		}
		proxmoxCAPEM = string(caData)
	}
	if s.StorageProfile == "dedicated-data-disk" {
		if err := storage.Initialize(ctx, runner, s.BootstrapAddress, *initialUser, s.StorageDevice, *storageConfirmed, false); err != nil {
			return err
		}
	}
	allowedDestinations := jumpDestinations(s)
	if err := proxmox.ConfigureIdentities(ctx, runner, s.BootstrapAddress, *initialUser, publicKey, allowedDestinations); err != nil {
		return fmt.Errorf("configure Proxmox administrative and bastion identities: %w", err)
	}
	if err := proxmox.ConfigureHeadlessPowerPolicy(ctx, runner, s.BootstrapAddress, *initialUser); err != nil {
		return err
	}
	fmt.Fprintln(out, "Headless power policy: PASS lid and idle suspend paths disabled")
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
		return errors.New("multiple eligible trunk interfaces require --trunk-interface selection before enrollment can mutate networking")
	}
	if s.Gateway.Mode == model.GatewayModeExternal && discovery.Trunk == nil {
		return errors.New("external gateway mode requires a distinct physical vmbr1 trunk interface")
	}
	if virtualOnlyRequested {
		if err := proxmox.EnsureVirtualOnlyBridge(ctx, client, apiNode, s.BootstrapAddress); err != nil {
			return err
		}
	} else if err := proxmox.EnsureVirtualBridge(ctx, client, apiNode); err != nil {
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
			return rollbackTrunkChange(ctx, client, apiNode, discovery.Trunk.Name, s.BootstrapAddress, "HOLD: enrollment network mutation could not be re-read", err)
		}
		return fmt.Errorf("HOLD: enrollment network state could not be re-read: %w", err)
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
			return rollbackTrunkChange(ctx, client, apiNode, discovery.Trunk.Name, s.BootstrapAddress, "HOLD: enrollment network mutation failed physical validation", err)
		}
		return fmt.Errorf("HOLD: enrollment network state failed physical validation: %w", err)
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
			return rollbackTrunkChange(ctx, client, apiNode, discovery.Trunk.Name, s.BootstrapAddress, "HOLD: enrollment network binding validation failed", err)
		}
		return fmt.Errorf("HOLD: enrollment network binding validation failed: %w", err)
	}
	if err := site.Save(*siteDir, s); err != nil {
		if trunkChanged {
			return rollbackTrunkChange(ctx, client, apiNode, discovery.Trunk.Name, s.BootstrapAddress, "HOLD: enrollment network binding could not be persisted", err)
		}
		return fmt.Errorf("HOLD: enrollment network binding could not be persisted: %w", err)
	}
	plan, err = proxmox.PlanFromSite(s)
	if err != nil {
		return fmt.Errorf("HOLD: recompute platform plan after physical binding: %w", err)
	}
	plan.Node = apiNode
	progress.complete()
	progress.start("persist", "Persist enrollment state")
	if err := writeBootstrapProjections(*siteDir, s); err != nil {
		return fmt.Errorf("HOLD: enrollment network binding was persisted but projections could not be regenerated: %w", err)
	}
	if err := writePhysicalDiscovery(*siteDir, s, postDiscovery); err != nil {
		return fmt.Errorf("HOLD: enrollment network binding was persisted but physical evidence could not be written: %w", err)
	}
	if err := site.Save(*siteDir, s); err != nil {
		return fmt.Errorf("HOLD: enrollment completed network mutation but physical binding could not be persisted: %w", err)
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
	fmt.Fprintf(out, "Proxmox enrollment: PASS authenticated with scoped identity on %s\n", version)
	if s.Gateway.Mode == model.GatewayModeManaged {
		fmt.Fprintln(out, "Managed gateway VM: deferred to boetticher deploy")
		fmt.Fprintf(out, "Managed gateway upstream MAC: %s (create the matching upstream DHCP reservation)\n", s.Gateway.Upstream.MAC)
	} else {
		fmt.Fprintln(out, "External gateway: PASS physical VLAN trunk recorded; appliance remains operator-managed")
	}
	fmt.Fprintln(out, "Initial root enrollment authentication: no longer required for routine boetticher access")
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

func inferredPrivateIdentity(publicKeyPath string) string {
	path := model.ExpandUserPath(publicKeyPath)
	if !strings.HasSuffix(path, ".pub") {
		return ""
	}
	return strings.TrimSuffix(path, ".pub")
}

func emitTiming(out io.Writer, stage string, started time.Time) {
	if out == nil || stage == "" || started.IsZero() {
		return
	}
	fmt.Fprintf(out, "timing stage=%s duration_ms=%d\n", stage, time.Since(started).Milliseconds())
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

// ansibleSourceRoot resolves the deployment playbook from the source
// checkout when present, or from the release controller's embedded public
// Ansible tree. The returned cleanup is a no-op for a checkout.
func ansibleSourceRoot() (string, func(), error) {
	root, err := applianceBuildSourceRoot()
	if err == nil {
		if _, statErr := os.Stat(filepath.Join(root, "ansible", "site.yml")); statErr == nil {
			return root, func() {}, nil
		}
		err = fmt.Errorf("Ansible deployment playbook is missing from %s", root)
	}
	archive, archiveErr := artifacts.BuildEmbeddedAnsibleSourceArchive()
	if archiveErr != nil {
		return "", func() {}, fmt.Errorf("resolve embedded Ansible source: %w (source checkout: %v)", archiveErr, err)
	}
	workspace, workspaceErr := os.MkdirTemp("", ".boetticher-ansible-source-*")
	if workspaceErr != nil {
		return "", func() {}, fmt.Errorf("create embedded Ansible source workspace: %w", workspaceErr)
	}
	if extractErr := artifacts.ExtractSourceArchiveReader(bytes.NewReader(archive), workspace); extractErr != nil {
		_ = os.RemoveAll(workspace)
		return "", func() {}, fmt.Errorf("extract embedded Ansible source: %w", extractErr)
	}
	return workspace, func() { _ = os.RemoveAll(workspace) }, nil
}
