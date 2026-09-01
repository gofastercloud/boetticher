package ansible

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/dns"
	"github.com/gofastercloud/boetticher/internal/firewall"
	"github.com/gofastercloud/boetticher/internal/gatus"
	"github.com/gofastercloud/boetticher/internal/logging"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/pulse"
	"github.com/gofastercloud/boetticher/internal/sshconfig"
	"github.com/gofastercloud/boetticher/internal/telemetry"
	"github.com/gofastercloud/boetticher/internal/usbexport"
)

const maxAnsibleOutputBytes = 64 * 1024
const maxAnsibleDiagnosticBytes = 16 * 1024

// The appliance inventory is small, but the network and services passes touch
// several independent guests. Eight forks removes avoidable host batching
// without creating unbounded load on a homelab controller or gateway. An
// explicit operator setting remains authoritative.
const defaultAnsibleForks = "8"

const (
	PhaseFull      = "full"
	PhaseBootstrap = "bootstrap"
	PhaseServices  = "services"
)

const maxAnsibleTaskTimings = 4096

// TaskTiming is deliberately limited to task identity, duration, and a small
// allow-listed set of secret-free observation markers. Ansible results can
// contain credentials, rendered configuration, and command output; none of
// that belongs in a deployment timing report.
type TaskTiming struct {
	Host       string   `json:"host"`
	Task       string   `json:"task"`
	Path       string   `json:"path"`
	Status     string   `json:"status"`
	DurationMS int64    `json:"duration_ms"`
	Changed    bool     `json:"changed"`
	Markers    []string `json:"markers,omitempty"`
}

type TaskBatchTiming struct {
	Task       string `json:"task"`
	Path       string `json:"path"`
	DurationMS int64  `json:"duration_ms"`
}

type RunResult struct {
	Changed          bool
	TaskTimings      []TaskTiming
	TaskBatchTimings []TaskBatchTiming
}

type boundedOutput struct {
	data           []byte
	prefix         []byte
	suffix         []byte
	diagnostic     []byte
	diagnosticScan []byte
	truncated      bool
}

func (b *boundedOutput) Write(data []byte) (int, error) {
	b.captureDiagnostics(data)
	if !b.truncated && len(b.data)+len(data) <= maxAnsibleOutputBytes {
		b.data = append(b.data, data...)
		return len(data), nil
	}
	if !b.truncated {
		prefixLimit := maxAnsibleOutputBytes / 2
		b.prefix = append(b.prefix, b.data[:minInt(len(b.data), prefixLimit)]...)
		b.suffix = retainSuffix(b.suffix, b.data, maxAnsibleOutputBytes-prefixLimit)
		b.data = nil
		b.truncated = true
	}
	prefixLimit := maxAnsibleOutputBytes / 2
	if len(b.prefix) < prefixLimit {
		keep := prefixLimit - len(b.prefix)
		if keep > len(data) {
			keep = len(data)
		}
		b.prefix = append(b.prefix, data[:keep]...)
	}
	suffixLimit := maxAnsibleOutputBytes - prefixLimit
	b.suffix = retainSuffix(b.suffix, data, suffixLimit)
	return len(data), nil
}

func (b *boundedOutput) captureDiagnostics(data []byte) {
	b.diagnosticScan = append(b.diagnosticScan, data...)
	for {
		index := bytes.IndexByte(b.diagnosticScan, '\n')
		if index < 0 {
			break
		}
		line := b.diagnosticScan[:index]
		b.diagnosticScan = b.diagnosticScan[index+1:]
		if !isDiagnosticLine(line) || len(b.diagnostic) >= maxAnsibleDiagnosticBytes {
			continue
		}
		remaining := maxAnsibleDiagnosticBytes - len(b.diagnostic)
		if len(line)+1 > remaining {
			line = line[:remaining-1]
		}
		b.diagnostic = append(b.diagnostic, line...)
		b.diagnostic = append(b.diagnostic, '\n')
	}
	if len(b.diagnosticScan) > maxAnsibleDiagnosticBytes {
		b.diagnosticScan = append([]byte(nil), b.diagnosticScan[len(b.diagnosticScan)-maxAnsibleDiagnosticBytes:]...)
	}
}

func isDiagnosticLine(line []byte) bool {
	text := string(line)
	return strings.Contains(text, "[ERROR]:") || strings.Contains(text, "fatal:") || strings.Contains(text, "FAILED!") || strings.Contains(text, "unreachable=")
}

func (b boundedOutput) DiagnosticBytes() []byte {
	return append([]byte(nil), b.diagnostic...)
}

func (b boundedOutput) Bytes() []byte {
	if !b.truncated {
		return append([]byte(nil), b.data...)
	}
	if len(b.prefix) == 0 {
		return append([]byte(nil), b.suffix...)
	}
	if len(b.suffix) == 0 {
		return append([]byte(nil), b.prefix...)
	}
	output := make([]byte, 0, len(b.prefix)+len(b.suffix)+len("\n[output truncated]\n"))
	output = append(output, b.prefix...)
	output = append(output, []byte("\n[output truncated]\n")...)
	output = append(output, b.suffix...)
	return output
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func retainSuffix(current, data []byte, limit int) []byte {
	if len(data) >= limit {
		return append([]byte(nil), data[len(data)-limit:]...)
	}
	combined := append(append([]byte(nil), current...), data...)
	if len(combined) > limit {
		combined = combined[len(combined)-limit:]
	}
	return combined
}

// MonitoringAgentTargets derives host-agent installation targets from the
// generic component tag. Monitoring is the only module that owns this
// projection; an untagged guest is never selected implicitly.
func MonitoringAgentTargets(s model.Site) []string {
	seen := map[string]bool{}
	result := make([]string, 0)
	for _, component := range s.PlatformComponents() {
		for _, tag := range component.Tags {
			if tag == model.TagMonitoringAgent && !seen[component.Name] {
				seen[component.Name] = true
				result = append(result, component.Name)
				break
			}
		}
	}
	sort.Strings(result)
	return result
}

func Inventory(s model.Site) (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	components := s.PlatformComponents()
	var b strings.Builder
	b.WriteString("# Generated by boetticher. Do not edit.\n")
	b.WriteString("# Model revision: ")
	revision, err := s.Revision()
	if err != nil {
		return "", err
	}
	b.WriteString(revision + "\n\n")
	groups := map[string][]model.Component{
		"dns": {}, "monitor": {}, "portal": {}, "logging": {},
		"tailnet-router": {}, "airvpn": {}, "litellm": {}, "printer": {}, "streamdeck": {}, "aiops": {}, "gatus": {},
	}
	if s.Gateway.Mode == model.GatewayModeManaged {
		groups["firewall"] = nil
	}
	var proxmoxComponent *model.Component
	for _, component := range components {
		if component.Name == "lab-proxmox-01" {
			copy := component
			proxmoxComponent = &copy
		}
		if component.Role == "DNS/NTP" {
			groups["dns"] = append(groups["dns"], component)
		}
		if component.Name == "lab-monitor-01" {
			groups["monitor"] = append(groups["monitor"], component)
		}
		if component.Name == "lab-portal-01" {
			groups["portal"] = append(groups["portal"], component)
		}
		if component.Name == "lab-log-01" {
			groups["logging"] = append(groups["logging"], component)
		}
		switch component.Module {
		case "tailnet-router", "airvpn", "litellm", "printer", "streamdeck", "aiops", "gatus":
			groups[component.Module] = append(groups[component.Module], component)
		}
	}
	if s.Gateway.Mode == model.GatewayModeManaged {
		for _, component := range components {
			if component.Name == "lab-fw-01" {
				groups["firewall"] = append(groups["firewall"], component)
				break
			}
		}
	}
	if proxmoxComponent == nil {
		return "", errors.New("Proxmox component is missing from the model")
	}
	b.WriteString("[proxmox]\n")
	address := proxmoxComponent.Address
	if s.BootstrapAddress != "" {
		address = s.BootstrapAddress
	}
	writeHostAt(&b, *proxmoxComponent, address)
	for _, group := range []string{"dns", "monitor", "portal", "logging", "tailnet-router", "airvpn", "litellm", "printer", "streamdeck", "aiops"} {
		writeInventoryGroup(&b, group, groups[group])
	}
	if s.Gateway.Mode == model.GatewayModeManaged {
		writeInventoryGroup(&b, "firewall", groups["firewall"])
	}
	writeInventoryGroup(&b, "gatus", groups["gatus"])
	b.WriteString("\n[managed:children]\nproxmox\ndns\nmonitor\nportal\nlogging\ntailnet-router\nairvpn\nlitellm\nprinter\nstreamdeck\naiops\ngatus\n")
	if s.Gateway.Mode == model.GatewayModeManaged {
		b.WriteString("firewall\n")
	}
	b.WriteString("\n")
	b.WriteString("[managed:vars]\nansible_connection=ssh\nansible_python_interpreter=/usr/bin/python3\nansible_remote_tmp=/tmp/boetticher-ansible\nansible_host_key_checking=true\n")
	return b.String(), nil
}

func writeInventoryGroup(b *strings.Builder, name string, components []model.Component) {
	fmt.Fprintf(b, "\n[%s]\n", name)
	for _, component := range components {
		writeHostAt(b, component, component.Address)
	}
}

func writeHostAt(b *strings.Builder, component model.Component, address string) {
	// The generated deployment inventory is used only during the temporary
	// root-SSH convergence window. Durable labadmin has no become boundary.
	fmt.Fprintf(b, "%s ansible_host=%s ansible_user=root", component.Name, address)
	b.WriteByte('\n')
}

func Variables(s model.Site) ([]byte, error) {
	return variables(s, nil, "", nil)
}

func VariablesWithUpstream(s model.Site, upstream firewall.UpstreamObservation) ([]byte, error) {
	return variables(s, &upstream, "", nil)
}

func VariablesWithOperatorKey(s model.Site, publicKey string) ([]byte, error) {
	return variables(s, nil, publicKey, nil)
}

func VariablesWithOperatorKeyAndUpstream(s model.Site, upstream firewall.UpstreamObservation, publicKey string) ([]byte, error) {
	return variables(s, &upstream, publicKey, nil)
}

func VariablesWithOperatorKeyAndAirVPN(s model.Site, publicKey string, profile firewall.AirVPNProfile) ([]byte, error) {
	return variables(s, nil, publicKey, &profile)
}

func VariablesWithAirVPN(s model.Site, profile firewall.AirVPNProfile) ([]byte, error) {
	return variables(s, nil, "", &profile)
}

func VariablesWithOperatorKeyAndUpstreamAndAirVPN(s model.Site, upstream firewall.UpstreamObservation, publicKey string, profile firewall.AirVPNProfile) ([]byte, error) {
	return variables(s, &upstream, publicKey, &profile)
}

func variables(s model.Site, upstream *firewall.UpstreamObservation, operatorPublicKey string, airvpnProfile *firewall.AirVPNProfile) ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	revision, err := s.Revision()
	if err != nil {
		return nil, err
	}
	gatusConfig, err := gatus.RenderConfiguration(s)
	if err != nil {
		return nil, err
	}
	dnsPlan, err := dns.PlanFromSite(s)
	if err != nil {
		return nil, err
	}
	monitoringPlan, err := pulse.PlanFromSite(s)
	if err != nil {
		return nil, err
	}
	var firewallPlan firewall.Plan
	if airvpnProfile != nil && upstream == nil {
		firewallPlan, err = firewall.PlanFromSiteWithAirVPN(s, *airvpnProfile)
	} else if airvpnProfile != nil {
		firewallPlan, err = firewall.PlanFromSiteWithUpstreamAndAirVPN(s, *upstream, *airvpnProfile)
	} else if upstream == nil {
		firewallPlan, err = firewall.PlanFromSite(s)
	} else {
		firewallPlan, err = firewall.PlanFromSiteWithUpstream(s, *upstream)
	}
	if err != nil {
		return nil, err
	}
	loggingPlan, err := logging.PlanFromSite(s)
	if err != nil {
		return nil, err
	}
	usbPlan, err := usbexport.PlanFromSite(s)
	if err != nil {
		return nil, err
	}
	var blockyConfig []byte
	blockyConfig, err = dns.RenderBlockyConfig(dnsPlan)
	if err != nil {
		return nil, err
	}
	loggingUploads := map[string]string{}
	for _, component := range s.PlatformComponents() {
		if component.Logging && component.Name != logging.CollectorName {
			loggingUploads[component.Name] = logging.UploadConfiguration(loggingPlan, component.Name)
		}
	}
	value := struct {
		ModelRevision                  string                                           `json:"model_revision"`
		Domain                         string                                           `json:"domain"`
		ProxmoxManagementAddress       string                                           `json:"proxmox_management_address"`
		IPv4Only                       bool                                             `json:"ipv4_only"`
		AuthoritativeDNS               string                                           `json:"authoritative_dns"`
		AuthoritativeDNSVersion        string                                           `json:"authoritative_dns_version"`
		AuthoritativePackageVersion    string                                           `json:"authoritative_package_version"`
		AuthoritativeDNSPort           string                                           `json:"authoritative_dns_port"`
		DynamicZones                   []string                                         `json:"dynamic_zones"`
		DNSPlan                        dns.Plan                                         `json:"dns_plan"`
		FirewallPlan                   firewall.Plan                                    `json:"firewall_plan"`
		FirewallInterfaceConfigDigests map[string]firewall.InterfaceConfigurationDigest `json:"firewall_interface_config_digests,omitempty"`
		MonitoringPlan                 pulse.Plan                                       `json:"monitoring_plan"`
		PulseAgentTargets              []string                                         `json:"pulse_agent_targets"`
		PulseAgentVersion              string                                           `json:"pulse_agent_version"`
		PulseAgentReleaseURL           string                                           `json:"pulse_agent_release_url"`
		PulseAgentReleaseSHA256        string                                           `json:"pulse_agent_release_sha256"`
		BlockyConfig                   string                                           `json:"blocky_config"`
		LoggingPlan                    logging.Plan                                     `json:"logging_plan"`
		LoggingCollectorConfig         string                                           `json:"logging_collector_config"`
		LoggingServiceOverride         string                                           `json:"logging_collector_service_override"`
		LoggingSocketOverride          string                                           `json:"logging_collector_socket_override"`
		LoggingUploadConfigs           map[string]string                                `json:"logging_upload_configs"`
		LoggingClientCertificates      map[string]string                                `json:"logging_client_certificates"`
		LoggingCollectorCertificate    string                                           `json:"logging_collector_certificate"`
		ModuleConfigs                  map[string]model.ModuleConfig                    `json:"module_configs"`
		ModuleDeclarations             []model.ModuleDeclaration                        `json:"module_declarations"`
		GatusConfig                    string                                           `json:"gatus_config"`
		USBExportManifests             []usbexport.GuestManifest                        `json:"usb_export_manifests"`
		NetworkProbeOperatorPublicKey  string                                           `json:"network_probe_operator_public_key,omitempty"`
	}{revision, s.Network.Domain, model.ProxmoxManagementAddress, true, dnsPlan.Implementation, dnsPlan.ImplementationVersion, dnsPlan.PackageVersion, dns.AuthoritativePort, dynamicZoneNames(dnsPlan.DynamicZones), dnsPlan, firewallPlan, firewall.GatewayInterfaceConfigurationDigests(firewallPlan), monitoringPlan, MonitoringAgentTargets(s), model.PulseAgentVersion, model.PulseAgentReleaseURL, model.PulseAgentReleaseSHA256, string(blockyConfig), loggingPlan, logging.CollectorConfiguration(loggingPlan), logging.CollectorServiceOverride(loggingPlan), logging.CollectorSocketOverride(loggingPlan), loggingUploads, map[string]string{}, "", s.ModuleConfig, s.Declarations, string(gatusConfig), usbPlan, operatorPublicKey}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func dynamicZoneNames(zones []dns.DynamicZone) []string {
	result := make([]string, 0, len(zones))
	for _, zone := range zones {
		result = append(result, zone.Name)
	}
	return result
}

// Run executes ansible-playbook with model variables over stdin. This keeps
// the invocation free of secret values and avoids a plaintext extra-vars
// file. The playbook itself must obtain any future secret material through an
// approved runtime mechanism.
func Run(ctx context.Context, playbook, inventory string, variables []byte) error {
	_, err := run(ctx, playbook, inventory, variables, "", PhaseFull)
	return err
}

// RunWithMutation reports only whether the bounded Ansible recap contained a
// non-zero changed count. It is intentionally not a per-resource audit log.
func RunWithMutation(ctx context.Context, playbook, inventory string, variables []byte) (bool, error) {
	result, err := run(ctx, playbook, inventory, variables, "", PhaseFull)
	return result.Changed, err
}

// RunWithMutationPhase is RunWithMutation with an explicit deployment phase
// exposed to the playbook. The phase is passed as extra-vars over stdin, not
// as an argv value, so the command line remains free of configuration data.
func RunWithMutationPhase(ctx context.Context, playbook, inventory string, variables []byte, phase string) (RunResult, error) {
	return run(ctx, playbook, inventory, variables, "", phase)
}

// RunLimited executes the same generated playbook against one known inventory
// identity. The limit is validated before it becomes an Ansible argument so a
// readiness stage cannot turn into an arbitrary command or host selector.
func RunLimited(ctx context.Context, playbook, inventory string, variables []byte, limit string) error {
	_, err := RunLimitedWithMutation(ctx, playbook, inventory, variables, limit)
	return err
}

// RunLimitedWithMutation is RunLimited with the same coarse changed signal as
// RunWithMutation.
func RunLimitedWithMutation(ctx context.Context, playbook, inventory string, variables []byte, limit string) (bool, error) {
	if !safeInventoryIdentity(limit) {
		return false, errors.New("Ansible limit must be one safe inventory identity")
	}
	result, err := run(ctx, playbook, inventory, variables, limit, PhaseFull)
	return result.Changed, err
}

// RunLimitedWithMutationPhase is the phase-aware form used by tracked deploy
// stages that also need to converge a single known inventory identity.
func RunLimitedWithMutationPhase(ctx context.Context, playbook, inventory string, variables []byte, limit, phase string) (RunResult, error) {
	if !safeInventoryIdentity(limit) {
		return RunResult{}, errors.New("Ansible limit must be one safe inventory identity")
	}
	return run(ctx, playbook, inventory, variables, limit, phase)
}

func run(ctx context.Context, playbook, inventory string, variables []byte, limit, phase string) (RunResult, error) {
	var empty RunResult
	if playbook == "" || inventory == "" {
		return empty, errors.New("Ansible playbook and inventory are required")
	}
	if err := sshconfig.ValidateExecutionConfig(generatedSSHConfigPath(inventory)); err != nil {
		return empty, fmt.Errorf("validate Ansible SSH configuration: %w", err)
	}
	executable, err := exec.LookPath("ansible-playbook")
	if err != nil {
		return empty, fmt.Errorf("ansible-playbook is required: %w", err)
	}
	variables, err = phaseVariables(variables, phase)
	if err != nil {
		return empty, err
	}
	args := []string{"-i", inventory, "--user", "root", playbook, "--extra-vars", "@/dev/stdin", "--ssh-common-args", "-F " + generatedSSHConfigPath(inventory)}
	if limit != "" {
		args = append(args, "--limit", limit)
	}
	command := exec.CommandContext(ctx, executable, args...)
	command.Stdin = strings.NewReader(string(variables))
	timingPath, timingCleanup := prepareTaskTiming(playbook)
	defer timingCleanup()
	command.Env = ansibleEnvironment(playbook, timingPath)
	var output boundedOutput
	command.Stdout = &output
	command.Stderr = &output
	started := time.Now()
	err = command.Run()
	changed := ansibleOutputChanged(output.Bytes())
	telemetry.Record(ctx, telemetry.Event{
		Category: "ansible", Operation: "playbook", Target: ansibleTarget(limit),
		Duration: time.Since(started), Success: err == nil, Changed: changed,
	})
	taskTimings, taskBatchTimings := readTaskTimings(timingPath)
	result := RunResult{Changed: changed, TaskTimings: taskTimings, TaskBatchTimings: taskBatchTimings}
	if err != nil {
		diagnostic := failureDiagnosticWithSupplement(output.Bytes(), output.DiagnosticBytes())
		if diagnostic == "" {
			return result, fmt.Errorf("ansible-playbook failed: %w", err)
		}
		return result, fmt.Errorf("ansible-playbook failed: %w: %s", err, diagnostic)
	}
	return result, nil
}

func phaseVariables(variables []byte, phase string) ([]byte, error) {
	if phase == "" {
		phase = PhaseFull
	}
	if phase != PhaseFull && phase != PhaseBootstrap && phase != PhaseServices {
		return nil, fmt.Errorf("unsupported Ansible deployment phase %q", phase)
	}
	var values map[string]any
	if err := json.Unmarshal(variables, &values); err != nil {
		return nil, fmt.Errorf("decode Ansible variables: %w", err)
	}
	if values == nil {
		return nil, errors.New("Ansible variables must be a JSON object")
	}
	values["boetticher_deploy_phase"] = phase
	data, err := json.MarshalIndent(values, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode Ansible variables: %w", err)
	}
	return append(data, '\n'), nil
}

func ansibleEnvironment(playbook, timingPath string) []string {
	environment := os.Environ()
	if _, ok := os.LookupEnv("ANSIBLE_FORKS"); !ok {
		environment = append(environment, "ANSIBLE_FORKS="+defaultAnsibleForks)
	}
	environment = setEnvironmentValue(environment, "ANSIBLE_HOST_KEY_CHECKING", "True")
	environment = setEnvironmentValue(environment, "ANSIBLE_SSH_PIPELINING", "True")
	pluginDir := filepath.Join(filepath.Dir(playbook), "callback_plugins")
	if _, err := os.Stat(filepath.Join(pluginDir, "boetticher_timing.py")); err == nil {
		environment = appendEnvironmentValue(environment, "ANSIBLE_CALLBACK_PLUGINS", pluginDir, string(os.PathListSeparator))
		environment = appendEnvironmentValue(environment, "ANSIBLE_CALLBACKS_ENABLED", "boetticher_timing", ",")
		if timingPath != "" {
			environment = setEnvironmentValue(environment, "BOETTICHER_ANSIBLE_TIMING_FILE", timingPath)
		}
	}
	return environment
}

func setEnvironmentValue(environment []string, key, value string) []string {
	prefix := key + "="
	for index, entry := range environment {
		if strings.HasPrefix(entry, prefix) {
			environment[index] = prefix + value
			return environment
		}
	}
	return append(environment, prefix+value)
}

func appendEnvironmentValue(environment []string, key, value, separator string) []string {
	prefix := key + "="
	for index, entry := range environment {
		if strings.HasPrefix(entry, prefix) {
			current := strings.TrimPrefix(entry, prefix)
			for _, part := range strings.Split(current, separator) {
				if part == value {
					return environment
				}
			}
			if current == "" {
				environment[index] = prefix + value
			} else {
				environment[index] = prefix + current + separator + value
			}
			return environment
		}
	}
	return append(environment, prefix+value)
}

func prepareTaskTiming(playbook string) (string, func()) {
	pluginPath := filepath.Join(filepath.Dir(playbook), "callback_plugins", "boetticher_timing.py")
	if _, err := os.Stat(pluginPath); err != nil {
		return "", func() {}
	}
	file, err := os.CreateTemp("", "boetticher-ansible-timing-*.jsonl")
	if err != nil {
		return "", func() {}
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", func() {}
	}
	return path, func() { _ = os.Remove(path) }
}

func readTaskTimings(path string) ([]TaskTiming, []TaskBatchTiming) {
	if path == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024), 16*1024)
	timings := make([]TaskTiming, 0)
	batchTimings := make([]TaskBatchTiming, 0)
	for scanner.Scan() && (len(timings) < maxAnsibleTaskTimings || len(batchTimings) < maxAnsibleTaskTimings) {
		var event struct {
			Event      string   `json:"event"`
			Host       string   `json:"host"`
			Task       string   `json:"task"`
			Path       string   `json:"path"`
			Status     string   `json:"status"`
			DurationMS int64    `json:"duration_ms"`
			Changed    bool     `json:"changed"`
			Markers    []string `json:"markers"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}
		switch event.Event {
		case "task_batch":
			if event.Task != "" && event.Path != "" && event.DurationMS >= 0 && len(batchTimings) < maxAnsibleTaskTimings {
				batchTimings = append(batchTimings, TaskBatchTiming{Task: event.Task, Path: event.Path, DurationMS: event.DurationMS})
			}
		default:
			if event.Host == "" || event.Task == "" || event.Status == "" || event.DurationMS < 0 || len(timings) >= maxAnsibleTaskTimings {
				continue
			}
			timings = append(timings, TaskTiming{Host: event.Host, Task: event.Task, Path: event.Path, Status: event.Status, DurationMS: event.DurationMS, Changed: event.Changed, Markers: event.Markers})
		}
	}
	return timings, batchTimings
}

func ansibleTarget(limit string) string {
	if limit == "" {
		return "all"
	}
	return limit
}

var ansibleChangedPattern = regexp.MustCompile(`changed=([0-9]+)`)

func ansibleOutputChanged(output []byte) bool {
	for _, match := range ansibleChangedPattern.FindAllSubmatch(output, -1) {
		if len(match) == 2 && string(match[1]) != "0" {
			return true
		}
	}
	return false
}

func failureDiagnostic(output []byte) string {
	return failureDiagnosticWithSupplement(output, nil)
}

func failureDiagnosticWithSupplement(output, supplement []byte) string {
	lines := strings.Split(string(output), "\n")
	if len(supplement) > 0 {
		lines = append(lines, strings.Split(string(supplement), "\n")...)
	}
	selected := make([]string, 0, 3)
	for _, line := range lines {
		if strings.Contains(line, "[ERROR]:") || strings.Contains(line, "fatal:") || strings.Contains(line, "unreachable=") {
			selected = append(selected, strings.TrimSpace(line))
		}
	}
	return strings.Join(selected, " | ")
}

// generatedSSHConfigPath derives the site-local SSH projection from the
// generated inventory location. Passing it directly to Ansible keeps the
// deploy transport independent of a user's global ~/.ssh/config includes.
func generatedSSHConfigPath(inventory string) string {
	return filepath.Clean(filepath.Join(filepath.Dir(inventory), "..", "ssh", "boetticher.conf"))
}

func safeInventoryIdentity(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.') {
			return false
		}
	}
	return true
}
