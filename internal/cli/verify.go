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

	"github.com/gofastercloud/boetticher/internal/backup"
	"github.com/gofastercloud/boetticher/internal/dns"
	"github.com/gofastercloud/boetticher/internal/firewall"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
	"github.com/gofastercloud/boetticher/internal/portal"
	"github.com/gofastercloud/boetticher/internal/proxmox"
	"github.com/gofastercloud/boetticher/internal/site"
	"github.com/gofastercloud/boetticher/internal/sshconfig"
	"github.com/gofastercloud/boetticher/internal/storage"
	"github.com/gofastercloud/boetticher/internal/zabbix"
)

func runVerify(args []string, out interface{ Write([]byte) (int, error) }) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	sshPath := fs.String("ssh-config", sshconfig.DefaultPath(), "generated SSH configuration to inspect")
	sshJourney := fs.Bool("ssh-journey", false, "run an authenticated internal SSH journey through the bastion")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "Modules")
	for _, module := range s.Modules {
		if module.Enabled {
			fmt.Fprintf(out, "  PASS  %-12s %s / %s (%s)\n", module.Name, module.Policy, module.State, module.Reason)
		} else {
			fmt.Fprintf(out, "  INFO  %-12s %s / Disabled\n", module.Name, module.Policy)
		}
	}
	for _, retained := range s.RetainedModules {
		fmt.Fprintf(out, "  INFO  %-12s retained resources remain boetticher-owned and inactive\n", retained.Module)
	}
	revision, err := s.Revision()
	if err != nil {
		return err
	}
	sshResult := portal.CheckResult{Name: "generated SSH configuration", Status: "NOT TESTED", Detail: "run boetticher ssh-config first"}
	if err := sshconfig.Check(*sshPath, s); err == nil {
		sshResult = portal.CheckResult{Name: "generated SSH configuration", Status: "PASS", Detail: "configuration is current and preserves host-key verification"}
	} else if !errors.Is(err, os.ErrNotExist) && !strings.Contains(err.Error(), "no such file") {
		sshResult = portal.CheckResult{Name: "generated SSH configuration", Status: "FAIL", Detail: err.Error()}
	}
	sshJourneyResult := portal.CheckResult{Name: "authenticated SSH journey via Proxmox bastion", Status: "NOT TESTED", Detail: "use --ssh-journey to exercise an internal host"}
	if *sshJourney {
		if sshResult.Status != "PASS" {
			sshJourneyResult.Detail = "generated SSH configuration is not current"
		} else if err := runSSHJourney(*sshPath); err != nil {
			sshJourneyResult = portal.CheckResult{Name: "authenticated SSH journey via Proxmox bastion", Status: "FAIL", Detail: err.Error()}
		} else {
			sshJourneyResult = portal.CheckResult{Name: "authenticated SSH journey via Proxmox bastion", Status: "PASS", Detail: "authenticated command completed through ProxyJump"}
		}
	}

	results := offlineVerificationResults(*siteDir, s)
	results = append(results,
		sshResult,
		sshJourneyResult,
		portal.CheckResult{Name: "DNS01/DNS02 reachable", Status: "NOT TESTED", Detail: "requires deployed network journey"},
		portal.CheckResult{Name: "NTP01/NTP02 synchronized", Status: "NOT TESTED", Detail: "requires deployed Chrony evidence"},
		portal.CheckResult{Name: "Proxmox API least privilege", Status: "NOT TESTED", Detail: "requires authenticated Proxmox API evidence"},
		portal.CheckResult{Name: "internal CA available", Status: "STATIC PASS", Detail: "CA metadata is present in the initialized model"},
		portal.CheckResult{Name: "portal requires client certificate", Status: "NOT TESTED", Detail: "requires deployed mTLS journey"},
		portal.CheckResult{Name: "Zabbix requires client certificate", Status: "NOT TESTED", Detail: "requires deployed mTLS journey"},
		portal.CheckResult{Name: "latest VM/LXC backup", Status: "NOT TESTED", Detail: "requires current backup evidence"},
		portal.CheckResult{Name: "Age recovery fixture", Status: "NOT TESTED", Detail: "requires independent recovery copy"},
	)
	if s.Gateway.Mode == model.GatewayModeManaged {
		results = append(results,
			portal.CheckResult{Name: "managed gateway services", Status: "NOT TESTED", Detail: "requires deployed managed gateway evidence"},
			portal.CheckResult{Name: "SANDBOX cannot access TRUSTED", Status: "NOT TESTED", Detail: "requires virtual-lab or live network journey"},
			portal.CheckResult{Name: "SANDBOX cannot access SERVERS", Status: "NOT TESTED", Detail: "requires virtual-lab or live network journey"},
			portal.CheckResult{Name: "SANDBOX cannot access MGMT", Status: "NOT TESTED", Detail: "requires virtual-lab or live network journey"},
			portal.CheckResult{Name: "MGMT DHCP is reservation-only", Status: "NOT TESTED", Detail: "requires deployed Kea evidence"},
		)
	} else {
		results = append(results, portal.CheckResult{Name: "external gateway contract", Status: "STATIC PASS", Detail: "required VLAN, gateway, DHCP, DNS, NTP, and policy intent is generated"})
	}
	fmt.Fprintln(out, "Modules")
	for _, module := range s.Modules {
		if module.Enabled {
			fmt.Fprintf(out, "  %-12s %s / %s\n", module.Name, module.Policy, module.State)
		} else {
			fmt.Fprintf(out, "  %-12s disabled / intentional\n", module.Name)
		}
	}
	if modules.IsEnabled(s, "logging") {
		fmt.Fprintln(out, "Logging                EXPECTED mandatory collector and asynchronous upload")
	}
	evidence := portal.Evidence{GeneratedAt: time.Now().UTC().Format(time.RFC3339), Results: results}
	document := struct {
		ModelRevision string          `json:"model_revision"`
		Evidence      portal.Evidence `json:"evidence"`
	}{ModelRevision: revision, Evidence: evidence}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	if err := writePublic(filepath.Join(*siteDir, "generated", "verification.json"), append(data, '\n')); err != nil {
		return err
	}
	overall := "HEALTHY"
	for _, result := range evidence.Results {
		if result.Status == "FAIL" {
			overall = "FAIL"
			break
		}
		if result.Status == "NOT TESTED" || result.Status == "HOLD" || result.Status == "INCONCLUSIVE" {
			overall = "PARTIAL"
		}
	}
	if err := writeProjection(filepath.Join(*siteDir, "generated", "status.json"), struct {
		ModelRevision string `json:"model_revision"`
		Status        string `json:"status"`
		GeneratedAt   string `json:"generated_at"`
	}{revision, overall, evidence.GeneratedAt}); err != nil {
		return err
	}
	if s.BootstrapAddress != "" {
		if err := rebuildPortal(*siteDir, s); err != nil {
			return err
		}
	}
	for _, result := range evidence.Results {
		fmt.Fprintf(out, "%-48s %s\n", result.Name, result.Status)
	}
	fmt.Fprintf(out, "Model revision: %s\n", revision)
	for _, result := range evidence.Results {
		if result.Status == "FAIL" {
			return errors.New("verification found a failed local check")
		}
	}
	return nil
}

func runDoctor(args []string, out interface{ Write([]byte) (int, error) }) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	sshPath := fs.String("ssh-config", sshconfig.DefaultPath(), "generated SSH configuration to check")
	live := fs.Bool("live", false, "perform bounded endpoint and SSH host-key checks")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	proxmoxCA := fs.String("proxmox-ca", "", "Proxmox API CA PEM file")
	insecure := fs.Bool("insecure", false, "explicitly allow self-signed Proxmox API TLS")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	revision, err := s.Revision()
	if err != nil {
		return err
	}
	checks := []struct {
		name  string
		path  string
		check func() error
	}{
		{"model projection", filepath.Join(*siteDir, "generated", "model.json"), func() error { return checkRevisionFile(filepath.Join(*siteDir, "generated", "model.json"), revision) }},
		{"status artifact", filepath.Join(*siteDir, "generated", "status.json"), func() error { return checkRevisionFile(filepath.Join(*siteDir, "generated", "status.json"), revision) }},
		{"inventory projection", filepath.Join(*siteDir, "generated", "inventory.json"), func() error {
			return checkRevisionFile(filepath.Join(*siteDir, "generated", "inventory.json"), revision)
		}},
		{"firewall policy", filepath.Join(*siteDir, "generated", "firewall", "desired-state.json"), func() error {
			return checkRevisionFile(filepath.Join(*siteDir, "generated", "firewall", "desired-state.json"), revision)
		}},
		{"DNS/DDNS policy", filepath.Join(*siteDir, "generated", "dns", "desired-state.json"), func() error {
			return checkRevisionFile(filepath.Join(*siteDir, "generated", "dns", "desired-state.json"), revision)
		}},
		{"physical discovery", filepath.Join(*siteDir, "generated", "network", "physical.json"), func() error {
			return checkRevisionFile(filepath.Join(*siteDir, "generated", "network", "physical.json"), revision)
		}},
		{"backup policy", filepath.Join(*siteDir, "generated", "backup", "desired-policy.json"), func() error {
			return checkRevisionFile(filepath.Join(*siteDir, "generated", "backup", "desired-policy.json"), revision)
		}},
		{"storage policy", filepath.Join(*siteDir, "generated", "storage", "desired-state.json"), func() error {
			return checkRevisionFile(filepath.Join(*siteDir, "generated", "storage", "desired-state.json"), revision)
		}},
		{"Proxmox desired state", filepath.Join(*siteDir, "generated", "proxmox", "desired-state.json"), func() error {
			return checkRevisionFile(filepath.Join(*siteDir, "generated", "proxmox", "desired-state.json"), revision)
		}},
		{"Monitoring policy", filepath.Join(*siteDir, "generated", "monitoring", "desired-state.json"), func() error {
			return checkRevisionFile(filepath.Join(*siteDir, "generated", "monitoring", "desired-state.json"), revision)
		}},
		{"Ansible inventory", filepath.Join(*siteDir, "generated", "ansible", "inventory.ini"), func() error {
			return checkRevisionFile(filepath.Join(*siteDir, "generated", "ansible", "inventory.ini"), revision)
		}},
		{"bastion policy", filepath.Join(*siteDir, "generated", "ssh", "lab-jump.conf"), func() error {
			return checkRevisionFile(filepath.Join(*siteDir, "generated", "ssh", "lab-jump.conf"), revision)
		}},
		{"SSH projection", filepath.Join(*siteDir, "generated", "ssh", "boetticher.conf"), func() error {
			return checkRevisionFile(filepath.Join(*siteDir, "generated", "ssh", "boetticher.conf"), revision)
		}},
		{"verification evidence", filepath.Join(*siteDir, "generated", "verification.json"), func() error {
			return checkRevisionFile(filepath.Join(*siteDir, "generated", "verification.json"), revision)
		}},
		{"portal", filepath.Join(*siteDir, "generated", "portal", "index.html"), func() error {
			return checkRevisionFile(filepath.Join(*siteDir, "generated", "portal", "index.html"), revision)
		}},
		{"SSH configuration", *sshPath, func() error { return sshconfig.Check(*sshPath, s) }},
	}
	checks = append(checks,
		struct {
			name  string
			path  string
			check func() error
		}{"Age identity", model.ExpandUserPath(*ageIdentity), func() error { return checkAgeIdentity(*ageIdentity) }},
		struct {
			name  string
			path  string
			check func() error
		}{"SOPS boundary", filepath.Join(*siteDir, "secrets"), func() error { return checkSOPSBoundary(*siteDir, s) }},
		struct {
			name  string
			path  string
			check func() error
		}{"runtime boundary", site.RuntimeDir(s), func() error { return checkRuntimeBoundary(*siteDir, s) }},
		struct {
			name  string
			path  string
			check func() error
		}{"platform ownership plan", filepath.Join(*siteDir, "generated", "proxmox", "desired-state.json"), func() error { return checkPlatformOwnership(s) }},
		struct {
			name  string
			path  string
			check func() error
		}{"qualified appliance evidence", filepath.Join(*siteDir, "generated", "artifacts"), func() error {
			_, err := qualifiedProxmoxPlan(*siteDir, s)
			return err
		}},
	)
	failed := false
	for _, check := range checks {
		if err := check.check(); err != nil {
			failed = true
			if errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "no such file") {
				fmt.Fprintf(out, "%-22s ABSENT (%s)\n", check.name, check.path)
			} else {
				fmt.Fprintf(out, "%-22s INCONSISTENT (%v)\n", check.name, err)
			}
		} else {
			fmt.Fprintf(out, "%-22s CURRENT\n", check.name)
		}
	}
	if s.PhysicalNetwork.Mode == model.ModeVirtualOnly {
		fmt.Fprintln(out, "Physical trunk        NOTICE virtual-only")
	} else {
		fmt.Fprintf(out, "Physical trunk        PASS %s attached\n", s.PhysicalNetwork.Trunk.Name)
	}
	if storagePlan, storageErr := storage.PlanFromSite(s); storageErr != nil {
		failed = true
		fmt.Fprintf(out, "Storage                INCONSISTENT (%v)\n", storageErr)
	} else {
		fmt.Fprintf(out, "Storage                CURRENT %s", storagePlan.Profile)
		if storagePlan.Device != "" {
			fmt.Fprintf(out, " device=%s", storagePlan.Device)
		}
		fmt.Fprintln(out)
	}
	if s.Gateway.Mode == model.GatewayModeManaged {
		fmt.Fprintln(out, "Managed gateway        NOT TESTED live Debian/nftables qualification requires deployment")
	} else {
		fmt.Fprintln(out, "External gateway       CONFIGURED appliance contract is outside boetticher management")
	}
	if s.BootstrapAddress == "" {
		fmt.Fprintln(out, "Bootstrap endpoint    ABSENT (record the HOME-side Proxmox address)")
	} else if !*live {
		fmt.Fprintf(out, "Bootstrap endpoint    NOT TESTED %s (use --live)\n", s.BootstrapAddress)
	} else if err := checkBootstrapEndpoint(*siteDir, s); err != nil {
		failed = true
		fmt.Fprintf(out, "Bootstrap endpoint    FAIL %v\n", err)
	} else {
		fmt.Fprintf(out, "Bootstrap endpoint    PASS %s and SSH host key\n", s.BootstrapAddress)
	}
	if *live {
		plan, planErr := qualifiedProxmoxPlan(*siteDir, s)
		if planErr != nil {
			failed = true
			fmt.Fprintf(out, "Platform guests       FAIL invalid platform plan: %v\n", planErr)
		} else if client, _, clientErr := loadProxmoxClient(*siteDir, s, *ageIdentity, *proxmoxCA, *insecure); clientErr != nil {
			fmt.Fprintf(out, "Platform guests       NOT TESTED (%v)\n", clientErr)
		} else if audits, auditErr := proxmox.AuditGuests(context.Background(), client, plan); auditErr != nil {
			failed = true
			fmt.Fprintf(out, "Platform guests       FAIL %v\n", auditErr)
		} else {
			userCount := 0
			retainedIDs := map[int]string{}
			for _, retained := range s.RetainedModules {
				for _, guest := range retained.Guests {
					retainedIDs[guest.VMID] = retained.Module
				}
			}
			for _, audit := range audits {
				if audit.Ownership == proxmox.UserOwnership {
					if module, retained := retainedIDs[audit.VMID]; retained {
						fmt.Fprintf(out, "Retained guest %-8d %-18s INFO module=%s inactive\n", audit.VMID, audit.Name, module)
						continue
					}
					userCount++
					continue
				}
				fmt.Fprintf(out, "Platform guest %-8d %-18s %s\n", audit.VMID, audit.Name, audit.Result)
				if audit.Result == "DRIFT" || audit.Result == "MISSING" {
					failed = true
				}
			}
			if userCount > 0 {
				fmt.Fprintf(out, "User-managed guests  INFO %d additional Proxmox guests detected; outside boetticher ownership\n", userCount)
			} else {
				fmt.Fprintln(out, "User-managed guests  INFO none detected")
			}
			var interfaces []proxmox.NetworkInterface
			if networkErr := client.NodeNetwork(context.Background(), s.ProxmoxNode, &interfaces); networkErr != nil {
				failed = true
				fmt.Fprintf(out, "Physical binding     FAIL %v\n", networkErr)
			} else if detail, bindingErr := proxmox.ValidatePhysicalBinding(s, interfaces); bindingErr != nil {
				failed = true
				fmt.Fprintf(out, "Physical binding     FAIL %v\n", bindingErr)
			} else {
				fmt.Fprintf(out, "Physical binding     PASS %s\n", detail)
			}
			storagePlan, storageErr := storage.PlanFromSite(s)
			if storageErr != nil {
				failed = true
				fmt.Fprintf(out, "Platform storage     FAIL %v\n", storageErr)
			} else if statuses, listErr := client.NodeStorage(context.Background(), s.ProxmoxNode); listErr != nil {
				failed = true
				fmt.Fprintf(out, "Platform storage     FAIL %v\n", listErr)
			} else if status, statusErr := expectedStorageStatus(statuses, storagePlan); statusErr != nil {
				failed = true
				fmt.Fprintf(out, "Platform storage     FAIL %v\n", statusErr)
			} else {
				fmt.Fprintf(out, "Platform storage     PASS %s active total=%.0f used=%.0f available=%.0f\n", status.Storage, status.Total, status.Used, status.Avail)
				if storagePlan.Profile == "dedicated-data-disk" {
					if err := reportDedicatedStorageHost(context.Background(), s, storagePlan, out); err != nil {
						failed = true
						fmt.Fprintf(out, "Storage layout       FAIL %v\n", err)
					}
				}
			}
		}
	} else {
		fmt.Fprintln(out, "Platform guests       NOT TESTED (use --live)")
	}
	if failed {
		return fmt.Errorf("doctor found absent or inconsistent projections")
	}
	return nil
}

func reportDedicatedStorageHost(ctx context.Context, s model.Site, plan storage.Plan, out interface{ Write([]byte) (int, error) }) error {
	command, err := storage.StatusCommand(plan.Device)
	if err != nil {
		return err
	}
	data, err := (proxmox.SSHRunner{}).Run(ctx, s.BootstrapAddress, model.DefaultAdminSSHUser, command)
	if err != nil {
		return fmt.Errorf("read dedicated storage state: %w", err)
	}
	status, err := storage.ParseStatus(string(data))
	if err != nil {
		return err
	}
	if status.Device != plan.Device || status.DevicePath == "missing" || status.VolumeGroup != plan.VolumeGroup || status.ThinPool != plan.ThinPool || status.BackupLV != plan.BackupLV || status.Filesystem != plan.Filesystem || status.Mount != plan.BackupMount || status.GuestStorage != "active" || status.BackupStorage != "active" {
		return fmt.Errorf("expected dedicated layout is not fully active: device=%s path=%s vg=%s thin=%s backup=%s filesystem=%s mount=%s guest=%s backup_storage=%s", status.Device, status.DevicePath, status.VolumeGroup, status.ThinPool, status.BackupLV, status.Filesystem, status.Mount, status.GuestStorage, status.BackupStorage)
	}
	fmt.Fprintf(out, "Storage layout       PASS %s mounted at %s\n", status.DevicePath, status.Mount)
	if status.Capacity != "" {
		fmt.Fprintf(out, "Storage capacity     INFO %s\n", status.Capacity)
	}
	return nil
}

func expectedStorageStatus(statuses []proxmox.StorageStatus, plan storage.Plan) (proxmox.StorageStatus, error) {
	wanted := []string{plan.GuestStorage}
	if plan.BackupStorage != plan.GuestStorage {
		wanted = append(wanted, plan.BackupStorage)
	}
	found := map[string]proxmox.StorageStatus{}
	for _, status := range statuses {
		found[status.Storage] = status
	}
	for _, id := range wanted {
		status, ok := found[id]
		if !ok {
			return proxmox.StorageStatus{}, fmt.Errorf("expected Proxmox storage %q is not registered", id)
		}
		if status.Active != 1 {
			return proxmox.StorageStatus{}, fmt.Errorf("expected Proxmox storage %q is not active", id)
		}
		if id == plan.GuestStorage {
			continue
		}
		return status, nil
	}
	return found[plan.GuestStorage], nil
}

func offlineVerificationResults(siteDir string, s model.Site) []portal.CheckResult {
	results := []portal.CheckResult{{Name: "canonical platform model validates", Status: "PASS", Detail: "fixed V1 topology and address contract validated locally"}}
	checks := []struct {
		name  string
		check func() error
	}{
		{"firewall policy projection", func() error {
			plan, err := firewall.PlanFromSite(s)
			if err != nil {
				return err
			}
			if !plan.IPv4Only || len(plan.Rules) == 0 {
				return errors.New("IPv4-only firewall policy is incomplete")
			}
			if s.Gateway.Mode == model.GatewayModeManaged {
				ruleset, renderErr := firewall.RenderNFT(plan)
				if renderErr != nil {
					return renderErr
				}
				if validateErr := firewall.ValidateNFT(ruleset); validateErr != nil {
					return validateErr
				}
			}
			return nil
		}},
		{"DNS/DDNS projection", func() error {
			plan, err := dns.PlanFromSite(s)
			if err != nil {
				return err
			}
			if len(plan.DynamicZones) != 4 {
				return errors.New("dynamic DNS zone contract is incomplete")
			}
			if s.Gateway.Mode == model.GatewayModeManaged && !plan.DDNS.Enabled {
				return errors.New("managed gateway dynamic DNS contract is disabled")
			}
			if s.Gateway.Mode == model.GatewayModeExternal && plan.DDNS.Enabled {
				return errors.New("external gateway must not claim managed DHCP/DDNS ownership")
			}
			return nil
		}},
		{"Zabbix platform projection", func() error {
			plan, err := zabbix.PlanFromSite(s)
			if err != nil {
				return err
			}
			if !plan.PlatformOnly || len(plan.Components) != len(s.PlatformComponents()) {
				return errors.New("Zabbix projection is not platform-only")
			}
			return nil
		}},
		{"platform backup projection", func() error {
			plan, err := backup.PlanFromSite(s)
			if err != nil {
				return err
			}
			if !plan.PlatformOnly || plan.UserWorkloadsManaged || len(plan.GuestVMIDs) != len(s.PlatformComponents())-1 {
				return errors.New("backup projection is not limited to platform guests")
			}
			return nil
		}},
		{"storage projection", func() error {
			plan, err := storage.PlanFromSite(s)
			if err != nil {
				return err
			}
			if plan.Profile == "dedicated-data-disk" && (plan.Device == "" || plan.GuestStorage != storage.GuestStorageID || plan.BackupStorage != storage.BackupStorageID) {
				return errors.New("dedicated storage projection is incomplete")
			}
			return nil
		}},
		{"qualified appliance evidence", func() error {
			_, err := qualifiedProxmoxPlan(siteDir, s)
			return err
		}},
		{"SSH bastion allow-list", func() error {
			policy, err := sshconfig.RenderBastionPolicy(s)
			if err != nil {
				return err
			}
			if !strings.Contains(policy, "PermitOpen") || strings.Contains(policy, "0.0.0.0") || strings.Contains(policy, "*") {
				return errors.New("bastion policy is not destination constrained")
			}
			return nil
		}},
		{"portal artifact", func() error {
			return checkRevisionFile(filepath.Join(siteDir, "generated", "portal", "index.html"), mustRevision(s))
		}},
	}
	for _, check := range checks {
		if err := check.check(); err != nil {
			results = append(results, portal.CheckResult{Name: check.name, Status: "FAIL", Detail: err.Error()})
		} else {
			results = append(results, portal.CheckResult{Name: check.name, Status: "STATIC PASS", Detail: "deterministic local projection is valid"})
		}
	}
	return results
}

func qualifiedProxmoxPlan(siteDir string, s model.Site) (proxmox.Plan, error) {
	plan, err := proxmox.PlanFromSite(s)
	if err != nil {
		return proxmox.Plan{}, err
	}
	return proxmox.ResolveQualifiedArtifacts(siteDir, plan, true)
}

func mustRevision(s model.Site) string {
	revision, err := s.Revision()
	if err != nil {
		return "invalid"
	}
	return revision
}

func checkPlatformOwnership(s model.Site) error {
	plan, err := proxmox.PlanFromSite(s)
	if err != nil {
		return err
	}
	want := []int{model.DNS01VMID, model.DNS02VMID, model.MonitorVMID, model.PortalVMID}
	if s.Gateway.Mode == model.GatewayModeManaged {
		want = append([]int{model.ProxmoxVMID}, want...)
	}
	if len(plan.Guests) != len(want) {
		return fmt.Errorf("platform plan contains %d guests; expected %d", len(plan.Guests), len(want))
	}
	for index, guest := range plan.Guests {
		if guest.VMID != want[index] {
			return fmt.Errorf("platform plan contains unexpected VMID %d", guest.VMID)
		}
	}
	return nil
}

func checkAgeIdentity(path string) error {
	path = model.ExpandUserPath(path)
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("Age identity must be a regular file, not a symlink or special file")
	}
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("Age identity permissions are %04o; group/other access must be absent", info.Mode().Perm())
	}
	return nil
}

func checkSOPSBoundary(siteDir string, s model.Site) error {
	config, err := os.ReadFile(filepath.Join(siteDir, ".sops.yaml"))
	if err != nil {
		return err
	}
	if !strings.Contains(string(config), s.SecretMetadata.AgeRecipient) || strings.Contains(string(config), "AGE-SECRET-KEY") {
		return errors.New(".sops.yaml must contain only the public Age recipient")
	}
	secretDir := filepath.Join(siteDir, "secrets")
	entries, err := os.ReadDir(secretDir)
	if err != nil {
		return err
	}
	found := false
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sops.yaml") {
			continue
		}
		found = true
		data, err := os.ReadFile(filepath.Join(secretDir, entry.Name()))
		if err != nil {
			return err
		}
		text := string(data)
		if !strings.Contains(text, "sops:") || !strings.Contains(text, "ENC[") || strings.Contains(text, "AGE-SECRET-KEY") || strings.Contains(text, "-----BEGIN PRIVATE KEY-----") {
			return fmt.Errorf("%s is not an encrypted SOPS document", entry.Name())
		}
	}
	if !found {
		return errors.New("no encrypted SOPS secret document exists")
	}
	return nil
}

func checkRuntimeBoundary(siteDir string, s model.Site) error {
	relative, err := filepath.Rel(filepath.Clean(siteDir), filepath.Clean(site.RuntimeDir(s)))
	if err != nil {
		return err
	}
	if relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
		return errors.New("runtime state is inside the site repository")
	}
	return nil
}
