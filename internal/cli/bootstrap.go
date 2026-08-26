package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/gofastercloud/boetticher/internal/artifacts"
	"github.com/gofastercloud/boetticher/internal/model"
	networkmodel "github.com/gofastercloud/boetticher/internal/network"
	"github.com/gofastercloud/boetticher/internal/proxmox"
	"github.com/gofastercloud/boetticher/internal/site"
	"github.com/gofastercloud/boetticher/internal/sshconfig"
	"github.com/gofastercloud/boetticher/internal/storage"
)

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

func runBootstrap(args []string, out interface{ Write([]byte) (int, error) }) error {
	fs := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	recoveryConfirmed := fs.Bool("recovery-confirmed", false, "confirm an independent Age recovery copy exists")
	storageConfirmed := fs.Bool("storage-confirmed", false, "confirm initialization of the configured dedicated data disk")
	operatorKey := fs.String("operator-key", "", "operator SSH public key path")
	initialUser := fs.String("initial-user", "root", "initial SSH user on the fresh Proxmox host")
	knownHosts := fs.String("known-hosts", "", "optional SSH known-hosts file for bootstrap")
	proxmoxCA := fs.String("proxmox-ca", "", "Proxmox API CA PEM file")
	insecure := fs.Bool("insecure", false, "explicitly allow self-signed Proxmox API TLS during bootstrap")
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
		fmt.Fprintf(out, "Bootstrap plan: PASS model %s\n", plan.ModelRevision)
		fmt.Fprintf(out, "  Proxmox endpoint: %s\n  Gateway mode: %s\n  Gateway image: %s\n", s.BootstrapAddress, s.Gateway.Mode, model.QualifiedGatewayImage)
		fmt.Fprintf(out, "  Storage: %s\n", s.StorageProfile)
		fmt.Fprintln(out, "  Trust transition: SSH key → labadmin/lab-jump → scoped API token → SOPS")
		builder := artifacts.Builder()
		fmt.Fprintf(out, "  Artifact builder: temporary VMID %d (%s, %s)\n", builder.VMID, builder.Hostname, builder.Network)
		fmt.Fprintln(out, "  Artifact qualification: base, selected appliances, SBOM, Trivy, independent content SHA-256")
		fmt.Fprintln(out, "  Destructive actions: NOT RUN (dry-run)")
		return nil
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
	if s.StorageProfile == "dedicated-data-disk" {
		if err := storage.Initialize(ctx, runner, s.BootstrapAddress, *initialUser, s.StorageDevice, *storageConfirmed); err != nil {
			return err
		}
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
		return errors.New("multiple eligible trunk interfaces require --trunk-interface selection before bootstrap can mutate networking")
	}
	if s.Gateway.Mode == model.GatewayModeExternal && discovery.Trunk == nil {
		return errors.New("external gateway mode requires a distinct physical vmbr1 trunk interface")
	}
	if err := proxmox.EnsureVirtualBridge(ctx, client, plan.Node); err != nil {
		return err
	}
	if err := proxmox.ConfigureManagementNetwork(ctx, runner, s.BootstrapAddress, *initialUser); err != nil {
		return err
	}
	if s.StorageProfile == "single-disk" {
		if err := client.EnsureDirectoryStorageContent(ctx, "local", "/var/lib/vz", []string{"backup", "images", "rootdir", "snippets"}); err != nil {
			return fmt.Errorf("ensure single-disk Proxmox storage: %w", err)
		}
	} else if err := client.EnsureDirectoryStorageContent(ctx, "local", "/var/lib/vz", []string{"images", "rootdir", "vztmpl", "snippets"}); err != nil {
		return fmt.Errorf("ensure local Proxmox artifact storage: %w", err)
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
	if err := buildDefaultArtifacts(ctx, client, plan, *siteDir, publicKey, *knownHosts, model.ExpandUserPath(s.SSHIdentityFile)); err != nil {
		return err
	}
	plan, err = proxmox.ResolveQualifiedArtifacts(*siteDir, plan, true)
	if err != nil {
		return err
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
	if s.Gateway.Mode == model.GatewayModeManaged {
		fmt.Fprintln(out, "Managed gateway VM: deferred to boetticher deploy")
	} else {
		fmt.Fprintln(out, "External gateway: PASS physical VLAN trunk recorded; appliance remains operator-managed")
	}
	fmt.Fprintln(out, "Initial root/bootstrap authentication: no longer required for routine boetticher access")
	return nil
}

func buildDefaultArtifacts(ctx context.Context, client *proxmox.Client, plan proxmox.Plan, siteDir, publicKey, knownHosts, identityFile string) error {
	base, err := artifacts.ArtifactFor("base")
	if err != nil {
		return err
	}
	if _, _, err := artifacts.ResolveArtifactEvidence(siteDir, base); err == nil {
		if _, err := proxmox.ResolveQualifiedArtifacts(siteDir, plan, true); err == nil {
			return nil
		}
	}
	if client == nil {
		return errors.New("Proxmox client is required for appliance construction")
	}
	sourceRoot, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("locate public build definitions: %w", err)
	}
	if _, err := os.Stat(filepath.Join(sourceRoot, "scripts", "build-images.sh")); err != nil {
		return fmt.Errorf("HOLD: public appliance build definitions are not available from %s: %w", sourceRoot, err)
	}
	if err := proxmox.EnsureBuilderVM(ctx, client, plan, publicKey); err != nil {
		return err
	}
	if err := client.StartVM(ctx, plan.Node, model.BuilderVMID); err != nil {
		return fmt.Errorf("start temporary appliance builder: %w", err)
	}
	builderAddress, err := proxmox.WaitForQEMUIPv4(ctx, client, plan.Node, model.BuilderVMID, 60, 5*time.Second)
	if err != nil {
		return err
	}
	builderRunner := proxmox.SSHRunner{KnownHosts: knownHosts, StrictHostKey: "accept-new", IdentityFile: identityFile}
	if err := proxmox.WaitForSSH(ctx, builderRunner, builderAddress, model.DefaultAdminSSHUser, 60, 5*time.Second); err != nil {
		return fmt.Errorf("HOLD: temporary appliance builder SSH is not ready: %w", err)
	}
	archive, err := artifacts.BuildSourceArchive(sourceRoot)
	if err != nil {
		return err
	}
	if _, err := builderRunner.RunWithStdin(ctx, builderAddress, model.DefaultAdminSSHUser, "set -eu; install -d -m 0755 /home/labadmin/build; tar -xzf - -C /home/labadmin/build", bytes.NewReader(archive)); err != nil {
		return fmt.Errorf("transfer public appliance build definitions: %w", err)
	}
	if _, err := builderRunner.Run(ctx, builderAddress, model.DefaultAdminSSHUser, "sudo -n /usr/local/sbin/boetticher-build"); err != nil {
		return fmt.Errorf("qualify default appliance artifacts on temporary builder: %w", err)
	}
	result, err := builderRunner.Run(ctx, builderAddress, model.DefaultAdminSSHUser, "tar -czf - -C /home/labadmin/build generated/artifacts")
	if err != nil {
		return fmt.Errorf("retrieve qualified appliance evidence: %w", err)
	}
	if err := artifacts.ExtractBuildArchive(result, siteDir); err != nil {
		return fmt.Errorf("extract qualified appliance evidence: %w", err)
	}
	if err := artifacts.RebindEvidencePaths(siteDir); err != nil {
		return fmt.Errorf("bind qualified evidence to controller artifact bytes: %w", err)
	}
	if err := proxmox.DestroyBuilderVM(ctx, client, plan.Node); err != nil {
		return err
	}
	return nil
}
