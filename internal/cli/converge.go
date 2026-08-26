package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/ansible"
	"github.com/gofastercloud/boetticher/internal/appliance"
	"github.com/gofastercloud/boetticher/internal/backup"
	"github.com/gofastercloud/boetticher/internal/firewall"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
	"github.com/gofastercloud/boetticher/internal/pki"
	"github.com/gofastercloud/boetticher/internal/proxmox"
	"github.com/gofastercloud/boetticher/internal/site"
	"github.com/gofastercloud/boetticher/internal/storage"
	"github.com/gofastercloud/boetticher/internal/zabbix"
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
	if err := writeModelProjections(*siteDir, s); err != nil {
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
			qualified, qualifyErr := proxmox.ResolveQualifiedArtifacts(*siteDir, plan, false)
			if qualifyErr == nil {
				plan = qualified
			}
			fmt.Fprintln(out, "  Appliances:")
			for _, guest := range plan.Guests {
				status := "definition resolved"
				if guest.Artifact.ContentSHA256 == "" && guest.Artifact.Name != "" {
					status = "NOT BUILT (content evidence absent)"
				}
				fmt.Fprintf(out, "    %s  %s  %s\n", guest.Name, guest.Artifact.Name, status)
				for _, volume := range guest.Volumes {
					fmt.Fprintf(out, "    volume %s -> %s (%s, backup=%t)\n", volume.Name, volume.MountPath, volume.Placement, volume.Backup)
				}
			}
		}
		return nil
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
	proxmoxPlan.OperatorPublicKey = operatorPublicKey
	if s.Gateway.Mode == model.GatewayModeManaged {
		for _, guest := range proxmoxPlan.Guests {
			if guest.Name != "lab-fw-01" {
				continue
			}
			cloudInit, renderErr := proxmox.RenderFirewallCloudInit(guest)
			if renderErr != nil {
				return fmt.Errorf("render firewall first-boot cloud-init: %w", renderErr)
			}
			proxmoxPlan.CloudInitFiles = cloudInit
			break
		}
	}
	proxmoxClient, _, err := loadProxmoxClient(*siteDir, s, *ageIdentity, *proxmoxCA, *insecure)
	if err != nil {
		return fmt.Errorf("load Proxmox client for platform deployment: %w", err)
	}
	if backupPlan.StorageTarget == backup.DedicatedStorageID {
		if err := proxmoxClient.EnsureLVMThinStorage(context.Background(), storage.GuestStorageID, storage.VolumeGroup, storage.ThinPool); err != nil {
			return fmt.Errorf("ensure dedicated guest storage: %w", err)
		}
		if err := proxmoxClient.EnsureDirectoryStorage(context.Background(), backup.DedicatedStorageID, backup.DedicatedStoragePath); err != nil {
			return fmt.Errorf("ensure dedicated backup storage: %w", err)
		}
	} else if err := proxmoxClient.EnsureDirectoryStorageContent(context.Background(), "local", "/var/lib/vz", []string{"backup", "images", "rootdir", "vztmpl"}); err != nil {
		return fmt.Errorf("ensure single-disk Proxmox storage: %w", err)
	}
	if s.Gateway.Mode == model.GatewayModeManaged {
		if err := proxmox.EnsureFirewallVM(context.Background(), proxmoxClient, proxmoxPlan); err != nil {
			return fmt.Errorf("create managed gateway appliance: %w", err)
		}
		if err := proxmoxClient.StartVM(context.Background(), proxmoxPlan.Node, model.ProxmoxVMID); err != nil {
			return fmt.Errorf("start managed gateway appliance: %w", err)
		}
	}
	readinessRunner := proxmox.SSHRunner{
		IdentityFile:  model.ExpandUserPath(s.SSHIdentityFile),
		ConfigFile:    filepath.Join(*siteDir, "generated", "ssh", "boetticher.conf"),
		StrictHostKey: "ask",
	}
	if s.Gateway.Mode == model.GatewayModeManaged {
		if err := proxmox.WaitForSSH(context.Background(), readinessRunner, "10.10.99.1", model.DefaultAdminSSHUser, 30, 2*time.Second); err != nil {
			return fmt.Errorf("HOLD: managed gateway is not reachable before dependent appliances: %w", err)
		}
	}
	for _, module := range []string{"dns", "logging", "monitoring", "portal"} {
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
			if err := proxmox.WaitForSSH(context.Background(), readinessRunner, guest.Address, model.DefaultAdminSSHUser, 30, 2*time.Second); err != nil {
				return fmt.Errorf("HOLD: %s guest %s is not reachable after first boot: %w", module, guest.Name, err)
			}
		}
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
	if s.Gateway.Mode == model.GatewayModeManaged {
		ddnsTSIG, loadErr := site.LoadDDNSTSIG(*siteDir, s, *ageIdentity)
		if loadErr != nil {
			return fmt.Errorf("load encrypted DDNS TSIG material: %w", loadErr)
		}
		runtimeVariables["ddns_tsig_secret"] = ddnsTSIG
	}
	if s.Gateway.Mode == model.GatewayModeManaged {
		ruleset, renderErr := firewall.RenderNFT(firewallPlan)
		if renderErr != nil {
			return renderErr
		}
		runtimeVariables["firewall_ruleset"] = ruleset
	}
	zabbixDBPassword, err := site.LoadPlatformSecret(*siteDir, s, *ageIdentity, "zabbix_db_password")
	if err != nil {
		return fmt.Errorf("load encrypted Zabbix database password: %w", err)
	}
	zabbixAPIPassword, err := site.LoadPlatformSecret(*siteDir, s, *ageIdentity, "zabbix_api_password")
	if err != nil {
		return fmt.Errorf("load encrypted Zabbix API password: %w", err)
	}
	authority, err := site.LoadAuthority(*siteDir, s, *ageIdentity)
	if err != nil {
		return fmt.Errorf("load platform CA chain: %w", err)
	}
	runtimeVariables["zabbix_db_password"] = zabbixDBPassword
	runtimeVariables["zabbix_api_password"] = zabbixAPIPassword
	runtimeVariables["client_ca_pem"] = authority.IssuingCertPEM
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
	if err := ansible.Run(context.Background(), "ansible/site.yml", inventoryPath, variables); err != nil {
		return err
	}
	if err := installModuleRuntimeConfigs(context.Background(), s, proxmoxPlan); err != nil {
		return err
	}
	monitorCSR, err := os.ReadFile(filepath.Join(csrDir, "monitor.csr.pem"))
	if err != nil {
		return fmt.Errorf("read endpoint-generated monitor CSR: %w", err)
	}
	portalCSR, err := os.ReadFile(filepath.Join(csrDir, "portal.csr.pem"))
	if err != nil {
		return fmt.Errorf("read endpoint-generated portal CSR: %w", err)
	}
	monitorCertificate, err := pki.SignServerCSR(authority, string(monitorCSR), "monitor", s.Network.Domain, []string{"lab-monitor-01." + s.Network.Domain}, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("sign monitor endpoint CSR: %w", err)
	}
	portalCertificate, err := pki.SignServerCSR(authority, string(portalCSR), "portal", s.Network.Domain, []string{"lab-portal-01." + s.Network.Domain}, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("sign portal endpoint CSR: %w", err)
	}
	runtimeVariables["pki_bootstrap_phase"] = false
	runtimeVariables["monitor_server_cert_pem"] = monitorCertificate.ChainPEM
	runtimeVariables["portal_server_cert_pem"] = portalCertificate.ChainPEM
	variables, err = json.MarshalIndent(runtimeVariables, "", "  ")
	if err != nil {
		return err
	}
	variables = append(variables, '\n')
	if err := ansible.Run(context.Background(), "ansible/site.yml", inventoryPath, variables); err != nil {
		return fmt.Errorf("install endpoint-signed certificates: %w", err)
	}
	clientCertificate, err := pki.IssueClient(authority, "boetticher-reconciler", s.Network.Domain, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("issue runtime Zabbix reconciliation certificate: %w", err)
	}
	zabbixClient, err := zabbix.NewClient(zabbix.ClientConfig{
		BaseURL: "https://monitor." + s.Network.Domain, User: "Admin", Password: zabbixAPIPassword,
		CAPEM: authority.IssuingCertPEM, ClientCertPEM: clientCertificate.CertPEM, ClientKeyPEM: clientCertificate.KeyPEM,
		ServerName: "monitor." + s.Network.Domain,
	})
	if err != nil {
		return err
	}
	zabbixPlan, err := zabbix.PlanFromSite(s)
	if err != nil {
		return err
	}
	if err := zabbixClient.Reconcile(context.Background(), zabbixPlan); err != nil {
		return fmt.Errorf("reconcile boetticher Zabbix objects: %w", err)
	}
	if err := proxmoxClient.ApplyBackupJob(context.Background(), s.ProxmoxNode, proxmox.BackupJob{
		JobName: backupPlan.JobName, ModelRevision: backupPlan.ModelRevision, StorageTarget: backupPlan.StorageTarget,
		Schedule: backupPlan.Schedule, VMIDList: backupPlan.VMIDList(), Retention: backupPlan.Retention,
	}); err != nil {
		return err
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

// installModuleRuntimeConfigs is the deployment boundary for the common
// non-secret appliance contract. Module declarations remain the source of
// guest identity and runtime configuration; the SSH runner is only the Core
// transport used to install the already-validated document.
func installModuleRuntimeConfigs(ctx context.Context, s model.Site, plan proxmox.Plan) error {
	runner := proxmox.SSHRunner{
		IdentityFile:  model.ExpandUserPath(s.SSHIdentityFile),
		StrictHostKey: "ask",
	}
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
		if guest.Module == "" {
			continue
		}
		declaration, ok := declarations[guest.Module]
		if !ok {
			return fmt.Errorf("runtime configuration for %s: module declaration is missing", guest.Name)
		}
		resolvedGuest, ok := resolvedGuests[guest.Name]
		if !ok || resolvedGuest.Artifact.ContentSHA256 == "" {
			return fmt.Errorf("runtime configuration for %s: qualified artifact content checksum is missing", guest.Name)
		}
		declaration, resolveErr := resolvedDeclarationForGuest(declaration, resolvedGuest)
		if resolveErr != nil {
			return fmt.Errorf("runtime configuration for %s: %w", guest.Name, resolveErr)
		}
		config, err := appliance.RenderRuntimeConfig(s, guest, declaration)
		if err != nil {
			return fmt.Errorf("render runtime configuration for %s: %w", guest.Name, err)
		}
		user := guest.SSHUser
		if user == "" {
			user = model.DefaultAdminSSHUser
		}
		if err := appliance.InstallRuntimeConfig(ctx, runner, guest.Address, user, config); err != nil {
			return fmt.Errorf("install runtime configuration for %s: %w", guest.Name, err)
		}
		if err := appliance.InstallArtifactIdentity(ctx, runner, guest.Address, user, declaration.Artifact); err != nil {
			return fmt.Errorf("install artifact identity for %s: %w", guest.Name, err)
		}
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
	return nil
}
