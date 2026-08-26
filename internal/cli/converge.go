package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gofastercloud/boetticher/internal/ansible"
	"github.com/gofastercloud/boetticher/internal/backup"
	"github.com/gofastercloud/boetticher/internal/firewall"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/pki"
	"github.com/gofastercloud/boetticher/internal/proxmox"
	"github.com/gofastercloud/boetticher/internal/site"
	"github.com/gofastercloud/boetticher/internal/storage"
	"github.com/gofastercloud/boetticher/internal/zabbix"
)

func runConverge(args []string, out interface{ Write([]byte) (int, error) }) error {
	fs := flag.NewFlagSet("converge", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	proxmoxCA := fs.String("proxmox-ca", "", "Proxmox API CA PEM file")
	zabbixURL := fs.String("zabbix-url", "https://monitor.lab.home.arpa", "Zabbix API base URL")
	insecure := fs.Bool("insecure", false, "explicitly allow self-signed Proxmox API TLS")
	playbook := fs.String("ansible-playbook", "ansible/site.yml", "guest convergence playbook")
	dryRun := fs.Bool("dry-run", false, "render and validate policy without connecting")
	if err := fs.Parse(args); err != nil {
		return err
	}
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
		fmt.Fprintf(out, "Gateway convergence plan: PASS model %s\n", firewallPlan.ModelRevision)
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
	proxmoxClient, _, err := loadProxmoxClient(*siteDir, s, *ageIdentity, *proxmoxCA, *insecure)
	if err != nil {
		return fmt.Errorf("load Proxmox client for platform convergence: %w", err)
	}
	if backupPlan.StorageTarget == backup.DedicatedStorageID {
		if err := proxmoxClient.EnsureLVMThinStorage(context.Background(), storage.GuestStorageID, storage.VolumeGroup, storage.ThinPool); err != nil {
			return fmt.Errorf("ensure dedicated guest storage: %w", err)
		}
		if err := proxmoxClient.EnsureDirectoryStorage(context.Background(), backup.DedicatedStorageID, backup.DedicatedStoragePath); err != nil {
			return fmt.Errorf("ensure dedicated backup storage: %w", err)
		}
	} else if err := proxmoxClient.EnsureDirectoryStorageContent(context.Background(), "local", "/var/lib/vz", []string{"backup", "images", "rootdir"}); err != nil {
		return fmt.Errorf("ensure single-disk Proxmox storage: %w", err)
	}
	ddnsTSIG, err := site.LoadDDNSTSIG(*siteDir, s, *ageIdentity)
	if err != nil {
		return fmt.Errorf("load encrypted DDNS TSIG material: %w", err)
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
	if err := ansible.Run(context.Background(), *playbook, inventoryPath, variables); err != nil {
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
	if err := ansible.Run(context.Background(), *playbook, inventoryPath, variables); err != nil {
		return fmt.Errorf("install endpoint-signed certificates: %w", err)
	}
	clientCertificate, err := pki.IssueClient(authority, "boetticher-reconciler", s.Network.Domain, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("issue runtime Zabbix reconciliation certificate: %w", err)
	}
	zabbixClient, err := zabbix.NewClient(zabbix.ClientConfig{
		BaseURL: *zabbixURL, User: "Admin", Password: zabbixAPIPassword,
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
	fmt.Fprintf(out, "Gateway convergence: PASS mode=%s model=%s (storage %s)\n", s.Gateway.Mode, firewallPlan.ModelRevision, storagePlan.GuestStorage)
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
	return nil
}
