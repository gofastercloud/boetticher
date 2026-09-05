package cli

import (
	"bytes"
	"context"
	"encoding/json"
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
	siteDir     string
	sshPath     string
	sshJourney  bool
	live        bool
	ageIdentity string
}

// collectHealthResults is the single result path shared by all status views.
// It only emits checks the command can perform now. Qualification gates that
// require an operator, an independent copy, or a separate network journey do
// not belong in this normal health report.
func collectHealthResults(options healthOptions, s model.Site) ([]statusmodel.CheckResult, string, error) {
	if options.ageIdentity == "" {
		options.ageIdentity = model.DefaultAgeIdentity
	}
	results := offlineVerificationResultsWithResolver(options.siteDir, s, net.LookupIP)
	results = append(results, deploymentOperationHealthResult(options.siteDir))

	sshConfigReady := false
	if err := sshconfig.Check(options.sshPath, s); err == nil {
		sshConfigReady = true
		results = append(results, checkResult(checkGeneratedSSHConfiguration, "PASS", "configuration is current and preserves host-key verification"))
	} else if !errors.Is(err, os.ErrNotExist) && !strings.Contains(err.Error(), "no such file") {
		results = append(results, checkResult(checkGeneratedSSHConfiguration, "FAIL", err.Error()))
	}
	if options.sshJourney {
		journey := checkResult(checkAuthenticatedSSHJourney, "", "")
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
		results = append(results, liveGatewayHealthResults(options.siteDir, s, options.ageIdentity)...)
		results = append(results, liveSmallstepHealthResults(options.siteDir, s)...)
	} else if s.Gateway.Mode == model.GatewayModeExternal {
		results = append(results, checkResult(checkExternalGatewayContract, "STATIC PASS", "required VLAN, gateway, DHCP, DNS, NTP, and policy intent is generated"))
	}

	observedAt := time.Now().UTC().Format(time.RFC3339)
	annotated, err := annotateVerificationEvidence(results, observedAt)
	if err != nil {
		return nil, "", err
	}
	return annotated, observedAt, nil
}

func liveSmallstepHealthResults(siteDir string, s model.Site) []statusmodel.CheckResult {
	dns, dnsOK := platformComponentByName(s, "lab-dns-01")
	monitor, monitorOK := platformComponentByName(s, "lab-monitor-01")
	if !dnsOK || !monitorOK || dns.Address == "" || monitor.Address == "" {
		return []statusmodel.CheckResult{
			checkResult(checkSmallstepCAService, "FAIL", "the core DNS and monitoring endpoints are not declared"),
			checkResult(checkPulseLeafCertificate, "FAIL", "the core monitoring endpoint is not declared"),
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	monitorRunner := applianceSSHRunner(s, siteDir, monitor.Hostname)
	caResult := checkResult(checkSmallstepCAService, "", "")
	healthURL := "https://lab-dns-01." + s.Network.Domain + ":9443/health"
	resolve := "lab-dns-01." + s.Network.Domain + ":9443:" + dns.Address
	healthData, err := monitorRunner.RunArgs(ctx, monitor.Address, model.DefaultAdminSSHUser, []string{"/usr/bin/curl", "--silent", "--show-error", "--fail", "--max-time", "5", "--cacert", "/etc/ssl/certs/ca-certificates.crt", "--resolve", resolve, healthURL})
	var health struct {
		Status string `json:"status"`
	}
	if err != nil || json.Unmarshal(bytes.TrimSpace(healthData), &health) != nil || health.Status != "ok" {
		caResult.Status = "FAIL"
		if err != nil {
			caResult.Detail = fmt.Sprintf("online CA health endpoint failed: %v", err)
		} else {
			caResult.Detail = "online CA health endpoint did not report status ok"
		}
	} else {
		caResult.Status = "PASS"
		caResult.Detail = "online CA health endpoint is active on the DNS endpoint"
	}

	leafResult := checkResult(checkPulseLeafCertificate, "", "")
	data, err := monitorRunner.Run(ctx, monitor.Address, model.DefaultAdminSSHUser, "/usr/bin/openssl s_client -connect 10.10.10.20:443 -servername monitor."+shellQuote(s.Network.Domain)+" -CAfile /etc/ssl/certs/ca-certificates.crt -verify_return_error </dev/null 2>/dev/null | /usr/bin/openssl x509 -noout -issuer -enddate")
	if err != nil {
		leafResult.Status = "FAIL"
		leafResult.Detail = fmt.Sprintf("read Pulse leaf certificate: %v", err)
	} else if expiry, parseErr := parseLeafExpiry(string(data)); parseErr != nil {
		leafResult.Status = "FAIL"
		leafResult.Detail = parseErr.Error()
	} else if !expiry.After(time.Now().UTC()) {
		leafResult.Status = "FAIL"
		leafResult.Detail = fmt.Sprintf("Pulse leaf certificate expired at %s", expiry.UTC().Format(time.RFC3339))
	} else {
		leafResult.Status = "PASS"
		leafResult.Detail = fmt.Sprintf("Pulse leaf certificate valid until %s (%s)", expiry.UTC().Format(time.RFC3339), strings.TrimSpace(string(data)))
	}
	return []statusmodel.CheckResult{caResult, leafResult}
}

func planFromLiveUpstream(siteDir string, s model.Site, ageIdentity string, upstream firewall.UpstreamObservation) (firewall.Plan, error) {
	if ageIdentity == "" {
		ageIdentity = model.DefaultAgeIdentity
	}
	profile, err := prepareAirVPNProfile(context.Background(), siteDir, s, ageIdentity, true, false)
	if err != nil {
		return firewall.Plan{}, err
	}
	if profile == nil {
		return firewall.PlanFromSiteWithUpstream(s, upstream)
	}
	return firewall.PlanFromSiteWithUpstreamAndAirVPN(s, upstream, profile.Metadata)
}

func platformComponentByName(s model.Site, name string) (model.Component, bool) {
	for _, component := range s.PlatformComponents() {
		if component.Name == name {
			return component, true
		}
	}
	return model.Component{}, false
}

func parseLeafExpiry(output string) (time.Time, error) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "notAfter=") {
			continue
		}
		value := strings.Join(strings.Fields(strings.TrimPrefix(line, "notAfter=")), " ")
		expiry, err := time.Parse("Jan 2 15:04:05 2006 MST", value)
		if err != nil {
			return time.Time{}, fmt.Errorf("parse Pulse leaf expiry %q: %w", value, err)
		}
		return expiry.UTC(), nil
	}
	return time.Time{}, errors.New("Pulse leaf certificate did not report an expiry")
}

func deploymentOperationHealthResult(siteDir string) statusmodel.CheckResult {
	result := checkResult(checkDeploymentOperationState, "", "")
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

func liveGatewayHealthResults(siteDir string, s model.Site, ageIdentity string) []statusmodel.CheckResult {
	fail := func(detail string) []statusmodel.CheckResult {
		return []statusmodel.CheckResult{
			checkResult(checkManagedGatewayUpstreamDHCP, "FAIL", detail),
			checkResult(checkPublishedServiceMapping, "FAIL", detail),
			checkResult(checkManagedGatewayServices, "FAIL", detail),
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
	services := checkResult(checkManagedGatewayServices, "PASS", serviceDetail)
	if err := validateDHCPServices(liveStatus); err != nil {
		services.Status = "FAIL"
		services.Detail = err.Error()
	}

	upstreamDetail := fmt.Sprintf("MAC %s address %s gateway %s", liveStatus.Upstream.MAC, liveStatus.Upstream.Address, liveStatus.Upstream.Gateway)
	upstream := checkResult(checkManagedGatewayUpstreamDHCP, "PASS", upstreamDetail)
	publication := checkResult(checkPublishedServiceMapping, "", "")
	if err := firewall.ValidateUpstreamObservation(plan, liveStatus.Upstream); err != nil {
		upstream.Status = "FAIL"
		upstream.Detail = err.Error()
		publication.Status = "FAIL"
		publication.Detail = "upstream observation is not safe for publication"
		return []statusmodel.CheckResult{upstream, publication, services}
	}
	livePlan, err := planFromLiveUpstream(siteDir, s, ageIdentity, liveStatus.Upstream)
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
		definition, err := normalizeCheckResult(&result)
		if err != nil {
			// collectHealthResults performs authoritative validation. Keep this
			// conversion total for callers that render a partial report.
			definition = checkDefinition{ID: result.ID, Label: result.Name, EvidenceTier: result.Tier}
		}
		checks = append(checks, statusmodel.LegacyCheck{
			ID: definition.ID, Name: definition.Label, Status: result.Status, Detail: result.Detail,
			Tier: definition.EvidenceTier, ObservedAt: result.ObservedAt,
			Reason: result.Reason, NextAction: result.NextAction,
		})
	}
	return statusmodel.FromLegacy(revision, observedAt, checks)
}

// annotateVerificationEvidence assigns tiers from the typed verification
// contract, not from human-readable labels or detail text.
func annotateVerificationEvidence(results []statusmodel.CheckResult, observedAt string) ([]statusmodel.CheckResult, error) {
	for index := range results {
		definition, err := normalizeCheckResult(&results[index])
		if err != nil {
			return nil, err
		}
		results[index].Name = definition.Label
		results[index].Tier = definition.EvidenceTier
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
	results := []statusmodel.CheckResult{checkResult(checkCanonicalPlatformModel, "PASS", "fixed 0.5 topology and address contract validated locally")}
	checks := []struct {
		id    string
		check func() error
	}{
		{checkFirewallPolicyProjection, func() error {
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
		{checkDNSDDNSProjection, func() error {
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
		{checkPulseMonitoringProjection, func() error {
			plan, err := pulse.PlanFromSite(s)
			if err != nil {
				return err
			}
			if !plan.PlatformOnly || len(plan.Components) != len(s.PlatformComponents()) {
				return errors.New("Pulse monitoring projection is not platform-only")
			}
			return nil
		}},
		{checkPlatformBackupProjection, func() error {
			plan, err := backup.PlanFromSite(s)
			if err != nil {
				return err
			}
			if !plan.PlatformOnly || plan.UserWorkloadsManaged || len(plan.GuestVMIDs) != len(s.PlatformComponents())-1 {
				return errors.New("backup projection is not limited to platform guests")
			}
			return nil
		}},
		{checkStorageProjection, func() error {
			plan, err := storage.PlanFromSite(s)
			if err != nil {
				return err
			}
			if plan.Profile == "dedicated-data-disk" && (plan.Device == "" || plan.GuestStorage != storage.GuestStorageID || plan.BackupStorage != storage.BackupStorageID) {
				return errors.New("dedicated storage projection is incomplete")
			}
			return nil
		}},
		{checkQualifiedApplianceEvidence, func() error {
			_, err := qualifiedProxmoxPlan(siteDir, s)
			return err
		}},
		{checkSSHBastionAllowList, func() error {
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
			results = append(results, checkResult(check.id, "FAIL", err.Error()))
		} else {
			results = append(results, checkResult(check.id, "STATIC PASS", "deterministic local projection is valid"))
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
