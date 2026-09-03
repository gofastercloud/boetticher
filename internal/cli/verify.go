package cli

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/backup"
	"github.com/gofastercloud/boetticher/internal/dns"
	"github.com/gofastercloud/boetticher/internal/firewall"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/proxmox"
	"github.com/gofastercloud/boetticher/internal/pulse"
	"github.com/gofastercloud/boetticher/internal/site"
	"github.com/gofastercloud/boetticher/internal/sshconfig"
	statusmodel "github.com/gofastercloud/boetticher/internal/status"
	"github.com/gofastercloud/boetticher/internal/storage"
)

type healthOptions struct {
	siteDir    string
	sshPath    string
	sshJourney bool
	live       bool
}

// collectHealthResults is the single result path shared by all status views.
// It only emits checks the command can perform now. Qualification gates that
// require an operator, an independent copy, or a separate network journey do
// not belong in this normal health report.
func collectHealthResults(options healthOptions, s model.Site) ([]statusmodel.CheckResult, string, error) {
	results := offlineVerificationResultsWithResolver(options.siteDir, s, net.LookupIP)
	results = append(results, deploymentOperationHealthResult(options.siteDir))

	sshConfigReady := false
	if err := sshconfig.Check(options.sshPath, s); err == nil {
		sshConfigReady = true
		results = append(results, statusmodel.CheckResult{Name: "generated SSH configuration", Status: "PASS", Detail: "configuration is current and preserves host-key verification"})
	} else if !errors.Is(err, os.ErrNotExist) && !strings.Contains(err.Error(), "no such file") {
		results = append(results, statusmodel.CheckResult{Name: "generated SSH configuration", Status: "FAIL", Detail: err.Error()})
	}
	if options.sshJourney {
		journey := statusmodel.CheckResult{Name: "authenticated SSH journey via Proxmox bastion", Tier: statusmodel.TierJourney}
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
		results = append(results, statusmodel.CheckResult{Name: "external gateway contract", Status: "STATIC PASS", Detail: "required VLAN, gateway, DHCP, DNS, NTP, and policy intent is generated"})
	}

	observedAt := time.Now().UTC().Format(time.RFC3339)
	annotated, err := annotateVerificationEvidence(results, observedAt)
	if err != nil {
		return nil, "", err
	}
	return annotated, observedAt, nil
}

func deploymentOperationHealthResult(siteDir string) statusmodel.CheckResult {
	result := statusmodel.CheckResult{Name: "deployment operation state", Tier: statusmodel.TierLocal}
	state, found, err := site.LoadOperationState(siteDir)
	if err != nil {
		result.Status = "FAIL"
		result.Detail = fmt.Sprintf("cannot read the deployment operation journal: %v", err)
		result.NextAction = "Repair or restore the private site journal before continuing."
		return result
	}
	if !found {
		result.Status = "PASS"
		result.Detail = "no incomplete deployment operation is recorded"
		return result
	}
	if state.TemporaryPublicKey != "" {
		result.Status = "HOLD"
		result.Detail = fmt.Sprintf("deployment journal is in %s and records temporary Apply cleanup", state.Phase)
		result.NextAction = "Run deploy with the reviewed plan to replay cleanup; use independent operator/root recovery if cleanup fails."
		return result
	}
	result.Status = "HOLD"
	result.Detail = fmt.Sprintf("deployment journal is in %s and stopped before temporary Apply authority", state.Phase)
	result.NextAction = "Review the failed deployment, then run deploy with a newly reviewed live plan."
	return result
}

func liveGatewayHealthResults(siteDir string, s model.Site) []statusmodel.CheckResult {
	upstreamName := "managed gateway upstream DHCP"
	publicationName := "published service mapping"
	servicesName := "managed gateway services"
	fail := func(detail string) []statusmodel.CheckResult {
		return []statusmodel.CheckResult{
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
	services := statusmodel.CheckResult{Name: servicesName, Status: "PASS", Detail: serviceDetail}
	if err := validateDHCPServices(liveStatus); err != nil {
		services.Status = "FAIL"
		services.Detail = err.Error()
	}

	upstreamDetail := fmt.Sprintf("MAC %s address %s gateway %s", liveStatus.Upstream.MAC, liveStatus.Upstream.Address, liveStatus.Upstream.Gateway)
	upstream := statusmodel.CheckResult{Name: upstreamName, Status: "PASS", Detail: upstreamDetail}
	publication := statusmodel.CheckResult{Name: publicationName}
	if err := firewall.ValidateUpstreamObservation(plan, liveStatus.Upstream); err != nil {
		upstream.Status = "FAIL"
		upstream.Detail = err.Error()
		publication.Status = "FAIL"
		publication.Detail = "upstream observation is not safe for publication"
		return []statusmodel.CheckResult{upstream, publication, services}
	}
	livePlan, err := firewall.PlanFromSiteWithUpstream(s, liveStatus.Upstream)
	if err != nil {
		publication.Status = "FAIL"
		publication.Detail = err.Error()
		return []statusmodel.CheckResult{upstream, publication, services}
	}
	ruleset, err := gatewayCommand(siteDir, s, "sudo", gatewayStatusScript, "ruleset")
	if err != nil {
		publication.Status = "FAIL"
		publication.Detail = fmt.Sprintf("read installed firewall ruleset: %v", err)
		return []statusmodel.CheckResult{upstream, publication, services}
	}
	diff, err := firewall.CompareNFT(livePlan, ruleset)
	if err != nil {
		publication.Status = "FAIL"
		publication.Detail = fmt.Sprintf("compare installed firewall ruleset: %v", err)
		return []statusmodel.CheckResult{upstream, publication, services}
	}
	if !diff.Current() {
		publication.Status = "FAIL"
		publication.Detail = fmt.Sprintf("installed firewall ruleset drift: %+v", diff)
		return []statusmodel.CheckResult{upstream, publication, services}
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
	return []statusmodel.CheckResult{upstream, publication, services}
}

func healthStatusReport(revision, observedAt string, results []statusmodel.CheckResult) statusmodel.Report {
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
func annotateVerificationEvidence(results []statusmodel.CheckResult, observedAt string) ([]statusmodel.CheckResult, error) {
	tiers := map[string]statusmodel.EvidenceTier{
		"canonical platform model validates":            statusmodel.TierLocal,
		"firewall policy projection":                    statusmodel.TierLocal,
		"DNS/DDNS projection":                           statusmodel.TierLocal,
		"Pulse monitoring projection":                   statusmodel.TierLocal,
		"platform backup projection":                    statusmodel.TierLocal,
		"storage projection":                            statusmodel.TierLocal,
		"qualified appliance evidence":                  statusmodel.TierLocal,
		"deployment operation state":                    statusmodel.TierLocal,
		"SSH bastion allow-list":                        statusmodel.TierLocal,
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

func offlineVerificationResults(siteDir string, s model.Site) []statusmodel.CheckResult {
	return offlineVerificationResultsWithResolver(siteDir, s, net.LookupIP)
}

func offlineVerificationResultsWithResolver(siteDir string, s model.Site, endpointLookup func(string) ([]net.IP, error)) []statusmodel.CheckResult {
	results := []statusmodel.CheckResult{{Name: "canonical platform model validates", Status: "PASS", Detail: "fixed 0.5 topology and address contract validated locally"}}
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
	}
	for _, check := range checks {
		if err := check.check(); err != nil {
			results = append(results, statusmodel.CheckResult{Name: check.name, Status: "FAIL", Detail: err.Error()})
		} else {
			results = append(results, statusmodel.CheckResult{Name: check.name, Status: "STATIC PASS", Detail: "deterministic local projection is valid"})
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
