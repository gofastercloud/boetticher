package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	aiopsmodel "github.com/gofastercloud/boetticher/internal/aiops"
	"github.com/gofastercloud/boetticher/internal/backup"
	"github.com/gofastercloud/boetticher/internal/dns"
	"github.com/gofastercloud/boetticher/internal/firewall"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
	"github.com/gofastercloud/boetticher/internal/pathguard"
	"github.com/gofastercloud/boetticher/internal/portal"
	"github.com/gofastercloud/boetticher/internal/proxmox"
	"github.com/gofastercloud/boetticher/internal/pulse"
	"github.com/gofastercloud/boetticher/internal/site"
	"github.com/gofastercloud/boetticher/internal/sshconfig"
	statusmodel "github.com/gofastercloud/boetticher/internal/status"
	"github.com/gofastercloud/boetticher/internal/storage"
)

func runVerify(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	sshPath := fs.String("ssh-config", sshconfig.DefaultPath(), "generated SSH configuration to inspect")
	sshJourney := fs.Bool("ssh-journey", false, "run an authenticated internal SSH journey through the bastion")
	live := fs.Bool("live", false, "inspect the managed gateway over the generated SSH path")
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
	results, verificationObservedAt, err := collectHealthResults(healthOptions{
		siteDir:    *siteDir,
		sshPath:    *sshPath,
		sshJourney: *sshJourney,
		live:       *live,
	}, s)
	if err != nil {
		return err
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
	evidence := portal.Evidence{GeneratedAt: verificationObservedAt, Results: results}
	semantic := healthStatusReport(revision, evidence.GeneratedAt, results)
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
	if err := writeProjection(filepath.Join(*siteDir, "generated", "status.json"), semantic); err != nil {
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
			return errors.New("verification found a failed health check")
		}
	}
	return nil
}

type healthOptions struct {
	siteDir    string
	sshPath    string
	sshJourney bool
	live       bool
}

// collectHealthResults is the single result path shared by status and verify.
// It only emits checks the command can perform now. Qualification gates that
// require an operator, an independent copy, or a separate network journey do
// not belong in this normal health report.
func collectHealthResults(options healthOptions, s model.Site) ([]portal.CheckResult, string, error) {
	endpointLookup, cancelEndpointLookup := verificationEndpointLookup(options.siteDir, s, options.live)
	defer cancelEndpointLookup()
	results := offlineVerificationResultsWithResolver(options.siteDir, s, endpointLookup)

	sshConfigReady := false
	if err := sshconfig.Check(options.sshPath, s); err == nil {
		sshConfigReady = true
		results = append(results, portal.CheckResult{Name: "generated SSH configuration", Status: "PASS", Detail: "configuration is current and preserves host-key verification"})
	} else if !errors.Is(err, os.ErrNotExist) && !strings.Contains(err.Error(), "no such file") {
		results = append(results, portal.CheckResult{Name: "generated SSH configuration", Status: "FAIL", Detail: err.Error()})
	}
	if options.sshJourney {
		journey := portal.CheckResult{Name: "authenticated SSH journey via Proxmox bastion", Tier: statusmodel.TierJourney}
		if !sshConfigReady {
			journey.Status = "FAIL"
			journey.Detail = "generated SSH configuration is not current"
		} else if err := runSSHJourney(options.sshPath); err != nil {
			journey.Status = "FAIL"
			journey.Detail = err.Error()
		} else {
			journey.Status = "PASS"
			journey.Detail = "authenticated command completed through ProxyJump"
		}
		results = append(results, journey)
	}
	if s.Gateway.Mode == model.GatewayModeManaged && options.live {
		results = append(results, liveGatewayHealthResults(options.siteDir, s)...)
	} else if s.Gateway.Mode == model.GatewayModeExternal {
		results = append(results, portal.CheckResult{Name: "external gateway contract", Status: "STATIC PASS", Detail: "required VLAN, gateway, DHCP, DNS, NTP, and policy intent is generated"})
	}

	observedAt := time.Now().UTC().Format(time.RFC3339)
	annotated, err := annotateVerificationEvidence(results, observedAt)
	if err != nil {
		return nil, "", err
	}
	return annotated, observedAt, nil
}

func liveGatewayHealthResults(siteDir string, s model.Site) []portal.CheckResult {
	upstreamName := "managed gateway upstream DHCP"
	publicationName := "published service mapping"
	servicesName := "managed gateway services"
	fail := func(detail string) []portal.CheckResult {
		return []portal.CheckResult{
			{Name: upstreamName, Status: "FAIL", Detail: detail},
			{Name: publicationName, Status: "FAIL", Detail: detail},
			{Name: servicesName, Status: "FAIL", Detail: detail},
		}
	}

	plan, err := firewall.PlanFromSite(s)
	if err != nil {
		return fail(err.Error())
	}
	data, err := gatewayCommand(siteDir, s, "sudo", gatewayStatusScript, "status")
	if err != nil {
		return fail(err.Error())
	}
	liveStatus, err := parseGatewayStatus(string(data))
	if err != nil {
		return fail(err.Error())
	}
	serviceDetail := fmt.Sprintf("nftables=%s, kea-dhcp4-server=%s, kea-dhcp-ddns-server=%s, dnsmasq=%s", liveStatus.Services["nftables"], liveStatus.Services["kea-dhcp4-server"], liveStatus.Services["kea-dhcp-ddns-server"], liveStatus.Services["dnsmasq"])
	services := portal.CheckResult{Name: servicesName, Status: "PASS", Detail: serviceDetail}
	if err := validateDHCPServices(liveStatus); err != nil {
		services.Status = "FAIL"
		services.Detail = err.Error()
	}

	upstreamDetail := fmt.Sprintf("MAC %s address %s gateway %s", liveStatus.Upstream.MAC, liveStatus.Upstream.Address, liveStatus.Upstream.Gateway)
	upstream := portal.CheckResult{Name: upstreamName, Status: "PASS", Detail: upstreamDetail}
	publication := portal.CheckResult{Name: publicationName}
	if err := firewall.ValidateUpstreamObservation(plan, liveStatus.Upstream); err != nil {
		upstream.Status = "FAIL"
		upstream.Detail = err.Error()
		publication.Status = "FAIL"
		publication.Detail = "upstream observation is not safe for publication"
		return []portal.CheckResult{upstream, publication, services}
	}
	livePlan, err := firewall.PlanFromSiteWithUpstream(s, liveStatus.Upstream)
	if err != nil {
		publication.Status = "FAIL"
		publication.Detail = err.Error()
		return []portal.CheckResult{upstream, publication, services}
	}
	ruleset, err := gatewayCommand(siteDir, s, "sudo", gatewayStatusScript, "ruleset")
	if err != nil {
		publication.Status = "FAIL"
		publication.Detail = fmt.Sprintf("read installed firewall ruleset: %v", err)
		return []portal.CheckResult{upstream, publication, services}
	}
	diff, err := firewall.CompareNFT(livePlan, ruleset)
	if err != nil {
		publication.Status = "FAIL"
		publication.Detail = fmt.Sprintf("compare installed firewall ruleset: %v", err)
		return []portal.CheckResult{upstream, publication, services}
	}
	if !diff.Current() {
		publication.Status = "FAIL"
		publication.Detail = fmt.Sprintf("installed firewall ruleset drift: %+v", diff)
		return []portal.CheckResult{upstream, publication, services}
	}
	if len(livePlan.Publications) == 0 {
		publication.Status = "STATIC PASS"
		publication.Detail = "no upstream publication is configured"
	} else {
		parts := make([]string, 0, len(livePlan.Publications))
		for _, item := range livePlan.Publications {
			parts = append(parts, fmt.Sprintf("%s:%d/%s -> %s", strings.Split(liveStatus.Upstream.Address, "/")[0], item.Port, item.Protocol, item.Destination))
		}
		publication.Status = "PASS"
		publication.Detail = strings.Join(parts, ", ")
	}
	return []portal.CheckResult{upstream, publication, services}
}

func healthStatusReport(revision, observedAt string, results []portal.CheckResult) statusmodel.Report {
	checks := make([]statusmodel.LegacyCheck, 0, len(results))
	for _, result := range results {
		checks = append(checks, statusmodel.LegacyCheck{
			Name: result.Name, Status: result.Status, Detail: result.Detail,
			Tier: result.Tier, ObservedAt: result.ObservedAt,
			Reason: result.Reason, NextAction: result.NextAction,
		})
	}
	return statusmodel.FromLegacy(revision, observedAt, checks)
}

// annotateVerificationEvidence assigns tiers from the verification contract,
// not from human-readable detail text. The map is deliberately explicit so a
// renamed or newly introduced check cannot inherit a stronger evidence claim.
func annotateVerificationEvidence(results []portal.CheckResult, observedAt string) ([]portal.CheckResult, error) {
	tiers := map[string]statusmodel.EvidenceTier{
		"canonical platform model validates":            statusmodel.TierLocal,
		"firewall policy projection":                    statusmodel.TierLocal,
		"DNS/DDNS projection":                           statusmodel.TierLocal,
		"Pulse monitoring projection":                   statusmodel.TierLocal,
		"platform backup projection":                    statusmodel.TierLocal,
		"storage projection":                            statusmodel.TierLocal,
		"qualified appliance evidence":                  statusmodel.TierLocal,
		"SSH bastion allow-list":                        statusmodel.TierLocal,
		"portal artifact":                               statusmodel.TierLocal,
		"generated SSH configuration":                   statusmodel.TierLocal,
		"authenticated SSH journey via Proxmox bastion": statusmodel.TierJourney,
		"managed gateway upstream DHCP":                 statusmodel.TierDeployed,
		"published service mapping":                     statusmodel.TierDeployed,
		"managed gateway services":                      statusmodel.TierDeployed,
		"external gateway contract":                     statusmodel.TierLocal,
	}
	for index := range results {
		if _, ok := tiers[results[index].Name]; !ok {
			return nil, fmt.Errorf("verification result %q is not in the evidence contract", results[index].Name)
		}
	}
	for index := range results {
		results[index].Tier = tiers[results[index].Name]
		if results[index].ObservedAt == "" {
			results[index].ObservedAt = observedAt
		}
	}
	return results, nil
}

func runDoctor(args []string, out io.Writer) error {
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
	return runDoctorRequest(doctorRequest{
		siteDir: *siteDir, sshPath: *sshPath, live: *live,
		ageIdentity: *ageIdentity, proxmoxCA: *proxmoxCA, insecure: *insecure,
	}, out)
}

type doctorRequest struct {
	siteDir     string
	sshPath     string
	live        bool
	ageIdentity string
	proxmoxCA   string
	insecure    bool
}

func runDoctorRequest(request doctorRequest, out io.Writer) error {
	siteDir, sshPath := request.siteDir, request.sshPath
	if siteDir == "" {
		siteDir = "."
	}
	if sshPath == "" {
		sshPath = sshconfig.DefaultPath()
	}
	ageIdentity := request.ageIdentity
	if ageIdentity == "" {
		ageIdentity = model.DefaultAgeIdentity
	}
	s, err := site.Load(siteDir)
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
		{"model projection", filepath.Join(siteDir, "generated", "model.json"), func() error { return checkRevisionFile(filepath.Join(siteDir, "generated", "model.json"), revision) }},
		{"status artifact", filepath.Join(siteDir, "generated", "status.json"), func() error { return checkRevisionFile(filepath.Join(siteDir, "generated", "status.json"), revision) }},
		{"inventory projection", filepath.Join(siteDir, "generated", "inventory.json"), func() error {
			return checkRevisionFile(filepath.Join(siteDir, "generated", "inventory.json"), revision)
		}},
		{"firewall policy", filepath.Join(siteDir, "generated", "firewall", "desired-state.json"), func() error {
			return checkRevisionFile(filepath.Join(siteDir, "generated", "firewall", "desired-state.json"), revision)
		}},
		{"DNS/DDNS policy", filepath.Join(siteDir, "generated", "dns", "desired-state.json"), func() error {
			return checkRevisionFile(filepath.Join(siteDir, "generated", "dns", "desired-state.json"), revision)
		}},
		{"physical discovery", filepath.Join(siteDir, "generated", "network", "physical.json"), func() error {
			return checkRevisionFile(filepath.Join(siteDir, "generated", "network", "physical.json"), revision)
		}},
		{"backup policy", filepath.Join(siteDir, "generated", "backup", "desired-policy.json"), func() error {
			return checkRevisionFile(filepath.Join(siteDir, "generated", "backup", "desired-policy.json"), revision)
		}},
		{"storage policy", filepath.Join(siteDir, "generated", "storage", "desired-state.json"), func() error {
			return checkRevisionFile(filepath.Join(siteDir, "generated", "storage", "desired-state.json"), revision)
		}},
		{"Proxmox desired state", filepath.Join(siteDir, "generated", "proxmox", "desired-state.json"), func() error {
			return checkRevisionFile(filepath.Join(siteDir, "generated", "proxmox", "desired-state.json"), revision)
		}},
		{"Monitoring policy", filepath.Join(siteDir, "generated", "monitoring", "desired-state.json"), func() error {
			return checkRevisionFile(filepath.Join(siteDir, "generated", "monitoring", "desired-state.json"), revision)
		}},
		{"Ansible inventory", filepath.Join(siteDir, "generated", "ansible", "inventory.ini"), func() error {
			return checkRevisionFile(filepath.Join(siteDir, "generated", "ansible", "inventory.ini"), revision)
		}},
		{"bastion policy", filepath.Join(siteDir, "generated", "ssh", "lab-jump.conf"), func() error {
			return checkRevisionFile(filepath.Join(siteDir, "generated", "ssh", "lab-jump.conf"), revision)
		}},
		{"SSH projection", filepath.Join(siteDir, "generated", "ssh", "boetticher.conf"), func() error {
			return checkRevisionFile(filepath.Join(siteDir, "generated", "ssh", "boetticher.conf"), revision)
		}},
		{"verification evidence", filepath.Join(siteDir, "generated", "verification.json"), func() error {
			return checkRevisionFile(filepath.Join(siteDir, "generated", "verification.json"), revision)
		}},
		{"portal", filepath.Join(siteDir, "generated", "portal", "index.html"), func() error {
			return checkRevisionFile(filepath.Join(siteDir, "generated", "portal", "index.html"), revision)
		}},
		{"SSH configuration", sshPath, func() error { return sshconfig.Check(sshPath, s) }},
	}
	checks = append(checks,
		struct {
			name  string
			path  string
			check func() error
		}{"Age identity", model.ExpandUserPath(ageIdentity), func() error { return checkAgeIdentity(ageIdentity) }},
		struct {
			name  string
			path  string
			check func() error
		}{"SOPS boundary", filepath.Join(siteDir, "secrets"), func() error { return checkSOPSBoundary(siteDir, s) }},
		struct {
			name  string
			path  string
			check func() error
		}{"runtime boundary", site.RuntimeDir(s), func() error { return checkRuntimeBoundary(siteDir, s) }},
		struct {
			name  string
			path  string
			check func() error
		}{"platform ownership plan", filepath.Join(siteDir, "generated", "proxmox", "desired-state.json"), func() error { return checkPlatformOwnership(s) }},
		struct {
			name  string
			path  string
			check func() error
		}{"qualified appliance evidence", filepath.Join(siteDir, "generated", "artifacts"), func() error {
			_, err := qualifiedProxmoxPlan(siteDir, s)
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
	if modules.IsEnabled(s, "aiops") {
		if !request.live {
			fmt.Fprintln(out, "AIOps                 NOT TESTED (use --live)")
		} else {
			var status bytes.Buffer
			if err := runAIOps([]string{"status", "--site", siteDir, "--live", "--json"}, &status); err != nil {
				failed = true
				fmt.Fprintf(out, "AIOps                 FAIL %v\n", err)
			} else {
				fmt.Fprintln(out, "AIOps                 PASS bounded live status available")
			}
			readiness, readinessErr := readAIOpsReadiness(siteDir, s)
			if readinessErr != nil {
				failed = true
				fmt.Fprintf(out, "AIOps readiness       FAIL %v\n", readinessErr)
			} else {
				for _, check := range []struct{ label, name string }{{"Pulse read path", aiopsmodel.ReadinessPulse}, {"Journal query path", aiopsmodel.ReadinessJournal}, {"AI Router alias", aiopsmodel.ReadinessRouter}} {
					result := readiness.Checks[check.name]
					if result != "PASS" {
						failed = true
						result = "FAIL"
					}
					fmt.Fprintf(out, "%-22s %s\n", check.label, result)
				}
			}
		}
	}
	if s.Gateway.Mode == model.GatewayModeManaged {
		if !request.live {
			fmt.Fprintln(out, "Managed gateway        NOT TESTED live Debian/nftables qualification requires deployment")
		} else if plan, planErr := firewall.PlanFromSite(s); planErr != nil {
			failed = true
			fmt.Fprintf(out, "Managed gateway        FAIL %v\n", planErr)
		} else if data, commandErr := gatewayCommand(siteDir, s, "sudo", gatewayStatusScript, "status"); commandErr != nil {
			failed = true
			fmt.Fprintf(out, "Managed gateway        FAIL %v\n", commandErr)
		} else if liveStatus, parseErr := parseGatewayStatus(string(data)); parseErr != nil {
			failed = true
			fmt.Fprintf(out, "Managed gateway        FAIL %v\n", parseErr)
		} else if observationErr := firewall.ValidateUpstreamObservation(plan, liveStatus.Upstream); observationErr != nil {
			failed = true
			fmt.Fprintf(out, "Upstream DHCP         HOLD %v\n", observationErr)
		} else {
			fmt.Fprintf(out, "Upstream DHCP         PASS MAC=%s address=%s gateway=%s\n", liveStatus.Upstream.MAC, liveStatus.Upstream.Address, liveStatus.Upstream.Gateway)
			for _, publication := range plan.Publications {
				fmt.Fprintf(out, "Published %s          PASS %s:%d/%s -> %s\n", strings.ToUpper(publication.Service), strings.Split(liveStatus.Upstream.Address, "/")[0], publication.Port, publication.Protocol, publication.Destination)
			}
			fmt.Fprintln(out, "Managed gateway        PASS live status and upstream identity verified")
		}
	} else {
		fmt.Fprintln(out, "External gateway       CONFIGURED appliance contract is outside boetticher management")
	}
	if s.BootstrapAddress == "" {
		fmt.Fprintln(out, "Bootstrap endpoint    ABSENT (record the HOME-side Proxmox address)")
	} else if !request.live {
		fmt.Fprintf(out, "Bootstrap endpoint    NOT TESTED %s (use --live)\n", s.BootstrapAddress)
	} else if err := checkBootstrapEndpoint(siteDir, s); err != nil {
		failed = true
		fmt.Fprintf(out, "Bootstrap endpoint    FAIL %v\n", err)
	} else {
		fmt.Fprintf(out, "Bootstrap endpoint    PASS %s and SSH host key\n", s.BootstrapAddress)
	}
	if request.live && s.BootstrapAddress != "" {
		if err := proxmox.CheckHeadlessPowerPolicy(context.Background(), proxmoxRootSSHRunner(s, siteDir), s.BootstrapAddress, "root"); err != nil {
			failed = true
			fmt.Fprintf(out, "Headless power       FAIL %v\n", err)
		} else {
			fmt.Fprintln(out, "Headless power       PASS lid and idle suspend paths disabled")
		}
	} else if !request.live {
		fmt.Fprintln(out, "Headless power       NOT TESTED (use --live)")
	}
	if request.live {
		plan, planErr := qualifiedProxmoxPlan(siteDir, s)
		if planErr != nil {
			failed = true
			fmt.Fprintf(out, "Platform guests       FAIL invalid platform plan: %v\n", planErr)
		} else if client, _, clientErr := loadProxmoxClient(siteDir, s, ageIdentity, request.proxmoxCA, request.insecure); clientErr != nil {
			fmt.Fprintf(out, "Platform guests       NOT TESTED (%v)\n", clientErr)
		} else if plan, nodeErr := bindPlanToLiveNode(context.Background(), client, plan); nodeErr != nil {
			failed = true
			fmt.Fprintf(out, "Platform guests       HOLD %v\n", nodeErr)
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
			if networkErr := client.NodeNetwork(context.Background(), plan.Node, &interfaces); networkErr != nil {
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
			} else if statuses, listErr := client.NodeStorage(context.Background(), plan.Node); listErr != nil {
				failed = true
				fmt.Fprintf(out, "Platform storage     FAIL %v\n", listErr)
			} else if status, statusErr := expectedStorageStatus(statuses, storagePlan); statusErr != nil {
				failed = true
				fmt.Fprintf(out, "Platform storage     FAIL %v\n", statusErr)
			} else {
				fmt.Fprintf(out, "Platform storage     PASS %s active total=%.0f used=%.0f available=%.0f\n", status.Storage, status.Total, status.Used, status.Avail)
				if storagePlan.Profile == "dedicated-data-disk" {
					if err := reportDedicatedStorageHost(context.Background(), siteDir, s, storagePlan, out); err != nil {
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

func bindPlanToLiveNode(ctx context.Context, client *proxmox.Client, plan proxmox.Plan) (proxmox.Plan, error) {
	node, err := client.SingleNode(ctx)
	if err != nil {
		return proxmox.Plan{}, err
	}
	plan.Node = node
	return plan, nil
}

func reportDedicatedStorageHost(ctx context.Context, siteDir string, s model.Site, plan storage.Plan, out io.Writer) error {
	command, err := storage.StatusCommand(plan.Device)
	if err != nil {
		return err
	}
	runner := proxmox.SSHRunner{
		IdentityFile:  operatorIdentityFile(s),
		ConfigFile:    filepath.Join(siteDir, "generated", "ssh", "boetticher.conf"),
		KnownHosts:    deploymentKnownHosts(siteDir),
		StrictHostKey: "yes",
		HostAlias:     model.LogicalProxmoxIdentity,
		HostKeyAlias:  model.LogicalProxmoxIdentity,
	}
	data, err := runner.Run(ctx, s.BootstrapAddress, "root", command)
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

func verificationEndpointLookup(siteDir string, s model.Site, live bool) (func(string) ([]net.IP, error), context.CancelFunc) {
	if !live || s.Gateway.Mode != model.GatewayModeManaged || strings.TrimSpace(s.BootstrapAddress) == "" {
		return net.LookupIP, func() {}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	rootRunner := proxmoxRootSSHRunner(s, siteDir)
	return endpointLookupWithFallback(net.LookupIP, remoteEndpointResolver(ctx, rootRunner, s.BootstrapAddress, "root")), cancel
}

func offlineVerificationResults(siteDir string, s model.Site) []portal.CheckResult {
	return offlineVerificationResultsWithResolver(siteDir, s, net.LookupIP)
}

func offlineVerificationResultsWithResolver(siteDir string, s model.Site, endpointLookup func(string) ([]net.IP, error)) []portal.CheckResult {
	results := []portal.CheckResult{{Name: "canonical platform model validates", Status: "PASS", Detail: "fixed 0.5 topology and address contract validated locally"}}
	checks := []struct {
		name  string
		check func() error
	}{
		{"firewall policy projection", func() error {
			plan, err := firewall.PlanFromSite(s)
			if err != nil {
				return err
			}
			if err := plan.Telemetry.Validate(); err != nil {
				return err
			}
			if s.Gateway.Mode == model.GatewayModeManaged && !plan.Telemetry.Enabled {
				return errors.New("managed firewall telemetry is disabled")
			}
			if s.Gateway.Mode == model.GatewayModeExternal && plan.Telemetry.Enabled {
				return errors.New("external firewall must not own telemetry")
			}
			if !plan.IPv4Only || len(plan.Rules) == 0 {
				return errors.New("IPv4-only firewall policy is incomplete")
			}
			if s.Gateway.Mode == model.GatewayModeManaged {
				ruleset, renderErr := renderDeploymentNFTWithResolver(plan, endpointLookup)
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
			if len(plan.DynamicZones) != 3 {
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
		{"Pulse monitoring projection", func() error {
			plan, err := pulse.PlanFromSite(s)
			if err != nil {
				return err
			}
			if !plan.PlatformOnly || len(plan.Components) != len(s.PlatformComponents()) {
				return errors.New("Pulse monitoring projection is not platform-only")
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
	wantSet := make(map[int]struct{})
	for _, component := range s.PlatformComponents() {
		if component.VMID != 0 {
			wantSet[component.VMID] = struct{}{}
		}
	}
	if len(plan.Guests) != len(wantSet) {
		return fmt.Errorf("platform plan contains %d guests; expected %d", len(plan.Guests), len(wantSet))
	}
	for _, guest := range plan.Guests {
		if _, ok := wantSet[guest.VMID]; !ok {
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
	config, err := pathguard.ReadFileLimited(filepath.Join(siteDir, ".sops.yaml"), site.MaxEncryptedDocumentBytes)
	if err != nil {
		return err
	}
	if !strings.Contains(string(config), s.SecretMetadata.AgeRecipient) || strings.Contains(string(config), "AGE-SECRET-KEY") {
		return errors.New(".sops.yaml must contain only the public Age recipient")
	}
	secretDir := filepath.Join(siteDir, "secrets")
	entries, err := pathguard.ReadDir(secretDir)
	if err != nil {
		return err
	}
	found := false
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sops.yaml") {
			continue
		}
		found = true
		data, err := pathguard.ReadFileLimited(filepath.Join(secretDir, entry.Name()), site.MaxEncryptedDocumentBytes)
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
	absSiteDir, err := filepath.Abs(siteDir)
	if err != nil {
		return err
	}
	relative, err := filepath.Rel(filepath.Clean(absSiteDir), filepath.Clean(site.RuntimeDir(s)))
	if err != nil {
		return err
	}
	if relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
		return errors.New("runtime state is inside the site repository")
	}
	return nil
}
