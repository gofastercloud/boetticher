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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gofastercloud/boetticher/internal/dns"
	"github.com/gofastercloud/boetticher/internal/firewall"
	"github.com/gofastercloud/boetticher/internal/gatus"
	"github.com/gofastercloud/boetticher/internal/logging"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/pathguard"
	"github.com/gofastercloud/boetticher/internal/pulse"
	"github.com/gofastercloud/boetticher/internal/sshconfig"
	"github.com/gofastercloud/boetticher/internal/telemetry"
	"github.com/gofastercloud/boetticher/internal/usbexport"
)

const maxAnsibleOutputBytes = 64 * 1024
const maxAnsibleDiagnosticBytes = 16 * 1024

var (
	sshAgentExecutable = "/usr/bin/ssh-agent"
	sshAddExecutable   = "/usr/bin/ssh-add"
)

// The appliance inventory is small, but the network and services passes touch
// several independent guests. Eight forks removes avoidable host batching
// without creating unbounded load on a homelab controller or gateway. An
// explicit operator setting remains authoritative.
const defaultAnsibleForks = "8"

const (
	// The converge orchestrator establishes the network foundation before its
	// all-host bootstrap pass, and the services pass follows it. Both passes
	// can progress independent guests without waiting at every task barrier.
	// Full and health remain linear to preserve ordered limited gates.
	defaultAnsibleStrategy  = "linear"
	parallelAnsibleStrategy = "free"
)

const (
	PhaseFull      = "full"
	PhaseBootstrap = "bootstrap"
	PhaseServices  = "services"
	PhaseHealth    = "health"
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
		"dns": {}, "monitor": {}, "logging": {},
		"tailnet-router": {}, "airvpn": {}, "bifrost": {}, "printer": {}, "arr": {}, "aiops": {}, "gatus": {},
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
		if component.Name == "lab-log-01" {
			groups["logging"] = append(groups["logging"], component)
		}
		switch component.Module {
		case "tailnet-router", "airvpn", "bifrost", "printer", "arr", "aiops", "gatus":
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
	for _, group := range []string{"dns", "monitor", "logging", "tailnet-router", "airvpn", "bifrost", "printer", "arr", "aiops"} {
		writeInventoryGroup(&b, group, groups[group])
	}
	if s.Gateway.Mode == model.GatewayModeManaged {
		writeInventoryGroup(&b, "firewall", groups["firewall"])
	}
	writeInventoryGroup(&b, "gatus", groups["gatus"])
	b.WriteString("\n[managed:children]\nproxmox\ndns\nmonitor\nlogging\ntailnet-router\nairvpn\nbifrost\nprinter\narr\naiops\ngatus\n")
	if s.Gateway.Mode == model.GatewayModeManaged {
		b.WriteString("firewall\n")
	}
	b.WriteString("\n")
	b.WriteString("[managed:vars]\nansible_connection=ssh\nansible_python_interpreter=/usr/bin/python3\nansible_remote_tmp=/var/lib/boetticher/ansible\nansible_host_key_checking=true\n")
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
	var loggingPlan logging.Plan
	var loggingCollectorConfig, loggingServiceOverride, loggingSocketOverride string
	loggingEnabled := false
	for _, component := range s.PlatformComponents() {
		if component.Module == "logging" {
			loggingEnabled = true
			break
		}
	}
	if loggingEnabled {
		loggingPlan, err = logging.PlanFromSite(s)
		if err != nil {
			return nil, err
		}
		loggingCollectorConfig = logging.CollectorConfiguration(loggingPlan)
		loggingServiceOverride = logging.CollectorServiceOverride(loggingPlan)
		loggingSocketOverride = logging.CollectorSocketOverride(loggingPlan)
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
		if loggingEnabled && component.Logging && component.Name != logging.CollectorName {
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
		ModuleConfigs                  map[string]model.ModuleConfig                    `json:"module_configs"`
		ModuleDeclarations             []model.ModuleDeclaration                        `json:"module_declarations"`
		GatusConfig                    string                                           `json:"gatus_config"`
		USBExportManifests             []usbexport.GuestManifest                        `json:"usb_export_manifests"`
		NetworkProbeOperatorPublicKey  string                                           `json:"network_probe_operator_public_key,omitempty"`
	}{revision, s.Network.Domain, model.ProxmoxManagementAddress, true, dnsPlan.Implementation, dnsPlan.ImplementationVersion, dnsPlan.PackageVersion, dns.AuthoritativePort, dynamicZoneNames(dnsPlan.DynamicZones), dnsPlan, firewallPlan, firewall.GatewayInterfaceConfigurationDigests(firewallPlan), monitoringPlan, MonitoringAgentTargets(s), model.PulseAgentVersion, model.PulseAgentReleaseURL, model.PulseAgentReleaseSHA256, string(blockyConfig), loggingPlan, loggingCollectorConfig, loggingServiceOverride, loggingSocketOverride, loggingUploads, s.ModuleConfig, s.Declarations, string(gatusConfig), usbPlan, operatorPublicKey}
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

// RunWithMutationPhase runs one bounded root convergence phase with
// an operation-scoped private key held only by a short-lived local agent. The
// key is never written to a file or placed in argv; the agent is destroyed
// before the phase returns.
func RunWithMutationPhase(ctx context.Context, playbook, inventory string, variables []byte, phase string, identityData []byte) (RunResult, error) {
	return run(ctx, playbook, inventory, variables, "", phase, identityData)
}

// RunExternal configures one external appliance through an operator-supplied
// temporary SSH configuration. The configuration must already pin the target
// host key and identity; this runner never falls back to the user's global
// SSH configuration.
func RunExternal(ctx context.Context, playbook, inventory string, variables []byte, sshConfig, user string) (RunResult, error) {
	if !safeInventoryIdentity(user) {
		return RunResult{}, errors.New("external Ansible user must be one safe inventory identity")
	}
	return runWithSSHConfig(ctx, playbook, inventory, variables, "", PhaseFull, sshConfig, user, nil)
}

// RunLimitedWithMutationPhase is the phase-aware form used by tracked deploy
// stages that also need to converge a single known inventory identity.
func RunLimitedWithMutationPhase(ctx context.Context, playbook, inventory string, variables []byte, limit, phase string, identityData []byte) (RunResult, error) {
	if !safeInventoryIdentity(limit) {
		return RunResult{}, errors.New("Ansible limit must be one safe inventory identity")
	}
	return run(ctx, playbook, inventory, variables, limit, phase, identityData)
}

func run(ctx context.Context, playbook, inventory string, variables []byte, limit, phase string, identityData []byte) (RunResult, error) {
	return runWithSSHConfig(ctx, playbook, inventory, variables, limit, phase, generatedSSHConfigPath(inventory), "root", identityData)
}

var findAnsiblePlaybook = ansiblePlaybookExecutable

func runWithSSHConfig(ctx context.Context, playbook, inventory string, variables []byte, limit, phase, sshConfig, user string, identityData []byte) (result RunResult, resultErr error) {
	var empty RunResult
	if playbook == "" || inventory == "" || sshConfig == "" || user == "" {
		return empty, errors.New("Ansible playbook, inventory, SSH configuration, and user are required")
	}
	if err := sshconfig.ValidateExecutionConfig(sshConfig); err != nil {
		return empty, fmt.Errorf("validate Ansible SSH configuration: %w", err)
	}
	executable, err := findAnsiblePlaybook()
	if err != nil {
		return empty, err
	}
	variables, err = phaseVariables(variables, phase)
	if err != nil {
		return empty, err
	}
	agentEnvironment := make(map[string]string)
	stopAgent := func() error { return nil }
	if len(identityData) > 0 {
		var agentErr error
		agentEnvironment, stopAgent, agentErr = startTemporarySSHAgent(identityData)
		if agentErr != nil {
			return empty, agentErr
		}
	}
	defer func() {
		if cleanupErr := stopAgent(); cleanupErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("stop temporary Ansible SSH agent: %w", cleanupErr))
		}
	}()
	sshArgs := "-F " + sshConfig
	if len(identityData) > 0 {
		// The target inventory user is root and must use the temporary
		// operation identity. IdentitiesOnly=no lets OpenSSH obtain that key
		// from the agent while the generated bastion host block retains its
		// durable, independently enrolled identity.
		sshArgs += " -o IdentitiesOnly=no -o ControlMaster=no -o ControlPath=none"
	}
	args := []string{"-i", inventory, "--user", user, playbook, "--extra-vars", "@/dev/stdin", "--ssh-common-args", sshArgs}
	if limit != "" {
		args = append(args, "--limit", limit)
	}
	command := exec.Command(executable, args...)
	command.Stdin = strings.NewReader(string(variables))
	timingPath, timingCleanup := prepareTaskTiming(playbook)
	defer timingCleanup()
	command.Env = ansibleEnvironment(playbook, timingPath, phase)
	for key, value := range agentEnvironment {
		command.Env = setEnvironmentValue(command.Env, key, value)
	}
	var output boundedOutput
	command.Stdout = &output
	command.Stderr = &output
	started := time.Now()
	err = runInProcessGroup(ctx, command)
	changed := ansibleOutputChanged(output.Bytes())
	telemetry.Record(ctx, telemetry.Event{
		Category: "ansible", Operation: "playbook", Target: ansibleTarget(limit),
		Duration: time.Since(started), Success: err == nil, Changed: changed,
	})
	taskTimings, taskBatchTimings := readTaskTimings(timingPath)
	result = RunResult{Changed: changed, TaskTimings: taskTimings, TaskBatchTimings: taskBatchTimings}
	if err != nil {
		diagnostic := failureDiagnosticWithSupplement(output.Bytes(), output.DiagnosticBytes())
		if diagnostic == "" {
			return result, fmt.Errorf("ansible-playbook failed: %w", err)
		}
		return result, fmt.Errorf("ansible-playbook failed: %w: %s", err, diagnostic)
	}
	return result, nil
}

func runInProcessGroup(ctx context.Context, command *exec.Cmd) error {
	if command == nil {
		return errors.New("Ansible command is required")
	}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return err
	}
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	select {
	case err := <-wait:
		return err
	case <-ctx.Done():
		if command.Process != nil {
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		}
		return errors.Join(ctx.Err(), <-wait)
	}
}

func startTemporarySSHAgent(identityData []byte) (map[string]string, func() error, error) {
	agent := exec.Command(sshAgentExecutable, "-s")
	output, err := agent.Output()
	if err != nil {
		return nil, func() error { return nil }, fmt.Errorf("start temporary Ansible SSH agent: %w", err)
	}
	environment, err := parseSSHAgentEnvironment(output)
	if err != nil {
		if cleanupErr := stopTemporarySSHAgent(environment); cleanupErr != nil {
			return nil, func() error { return nil }, errors.Join(err, fmt.Errorf("cleanup temporary Ansible SSH agent: %w", cleanupErr))
		}
		return nil, func() error { return nil }, err
	}
	stop := func() error {
		return stopTemporarySSHAgent(environment)
	}
	add := exec.Command(sshAddExecutable, "-")
	add.Env = append(os.Environ(), "SSH_AUTH_SOCK="+environment["SSH_AUTH_SOCK"], "SSH_AGENT_PID="+environment["SSH_AGENT_PID"])
	add.Stdin = bytes.NewReader(identityData)
	if output, err := add.CombinedOutput(); err != nil {
		loadErr := fmt.Errorf("load temporary Ansible SSH identity: %w (%s)", err, strings.TrimSpace(string(output)))
		if cleanupErr := stop(); cleanupErr != nil {
			return nil, func() error { return nil }, errors.Join(loadErr, fmt.Errorf("cleanup temporary Ansible SSH agent: %w", cleanupErr))
		}
		return nil, func() error { return nil }, loadErr
	}
	return environment, stop, nil
}

func stopTemporarySSHAgent(environment map[string]string) error {
	if environment == nil {
		return errors.New("ssh-agent environment is unavailable")
	}
	socket, socketOK := environment["SSH_AUTH_SOCK"]
	pid, pidOK := environment["SSH_AGENT_PID"]
	if socketOK && pidOK {
		kill := exec.Command(sshAgentExecutable, "-k")
		kill.Env = append(os.Environ(), "SSH_AUTH_SOCK="+socket, "SSH_AGENT_PID="+pid)
		if output, err := kill.CombinedOutput(); err == nil {
			return nil
		} else if validAgentPID(pid) {
			if killErr := syscall.Kill(parseAgentPID(pid), syscall.SIGTERM); killErr == nil {
				return nil
			} else {
				return fmt.Errorf("ssh-agent cleanup failed: %w (%s); direct termination failed: %v", err, strings.TrimSpace(string(output)), killErr)
			}
		} else {
			return fmt.Errorf("ssh-agent cleanup failed: %w (%s)", err, strings.TrimSpace(string(output)))
		}
	}
	if validAgentPID(pid) {
		if err := syscall.Kill(parseAgentPID(pid), syscall.SIGTERM); err == nil {
			return nil
		} else {
			return fmt.Errorf("ssh-agent direct cleanup failed: %w", err)
		}
	}
	return errors.New("ssh-agent returned no safe cleanup process id")
}

func validAgentPID(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func parseAgentPID(value string) int {
	pid, _ := strconv.Atoi(value)
	return pid
}

func parseSSHAgentEnvironment(output []byte) (map[string]string, error) {
	values := make(map[string]string, 2)
	for _, line := range strings.Split(string(output), "\n") {
		for _, key := range []string{"SSH_AUTH_SOCK", "SSH_AGENT_PID"} {
			prefix := key + "="
			if !strings.HasPrefix(line, prefix) {
				continue
			}
			value := strings.SplitN(strings.TrimPrefix(line, prefix), ";", 2)[0]
			if value == "" || strings.IndexFunc(value, func(r rune) bool {
				return r == '\x00' || r == '\r' || r == '\n' || r == ' ' || r == '\t'
			}) >= 0 {
				return values, errors.New("ssh-agent returned an unsafe environment value")
			}
			values[key] = value
		}
	}
	if values["SSH_AUTH_SOCK"] == "" || values["SSH_AGENT_PID"] == "" {
		return values, errors.New("ssh-agent did not return SSH_AUTH_SOCK and SSH_AGENT_PID")
	}
	for _, r := range values["SSH_AGENT_PID"] {
		if r < '0' || r > '9' {
			return values, errors.New("ssh-agent returned an invalid process id")
		}
	}
	return values, nil
}

func phaseVariables(variables []byte, phase string) ([]byte, error) {
	if phase == "" {
		phase = PhaseFull
	}
	if phase != PhaseFull && phase != PhaseBootstrap && phase != PhaseServices && phase != PhaseHealth {
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

func ansibleEnvironment(playbook, timingPath, phase string) []string {
	environment := make([]string, 0, len(os.Environ())+8)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "ANSIBLE_") || key == "PYTHONPATH" || key == "PYTHONHOME" || key == "PYTHONUSERBASE" || key == "VIRTUAL_ENV" || key == "PIP_CONFIG_FILE" {
			continue
		}
		environment = append(environment, entry)
	}
	environment = setEnvironmentValue(environment, "PATH", safeControllerPath)
	// Ansible 2.21 rejects configuration paths without a supported extension;
	// this nonexistent .cfg path still disables discovery of ambient config.
	environment = setEnvironmentValue(environment, "ANSIBLE_CONFIG", "/dev/null.cfg")
	environment = setEnvironmentValue(environment, "ANSIBLE_FORKS", defaultAnsibleForks)
	environment = setEnvironmentValue(environment, "PYTHONNOUSERSITE", "1")
	strategy := defaultAnsibleStrategy
	if phase == PhaseBootstrap || phase == PhaseServices {
		strategy = parallelAnsibleStrategy
	}
	// Keep the strategy deterministic for every deploy phase. In particular,
	// an ambient ANSIBLE_STRATEGY=free must not weaken ordering in the network
	// foundation or health phases.
	environment = setEnvironmentValue(environment, "ANSIBLE_STRATEGY", strategy)
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

const safeControllerPath = "/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"

func ansiblePlaybookExecutable() (string, error) {
	for _, directory := range strings.Split(safeControllerPath, string(os.PathListSeparator)) {
		candidate := filepath.Join(directory, "ansible-playbook")
		resolved, err := filepath.EvalSymlinks(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("inspect ansible-playbook: %w", err)
		}
		if !filepath.IsAbs(resolved) {
			return "", errors.New("ansible-playbook resolved to a non-absolute path")
		}
		if err := pathguard.ValidateNoSymlinkComponents(resolved); err != nil {
			return "", fmt.Errorf("validate ansible-playbook path: %w", err)
		}
		info, err := os.Stat(resolved)
		if err != nil {
			return "", fmt.Errorf("stat ansible-playbook: %w", err)
		}
		if !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
			return "", errors.New("ansible-playbook must be an executable regular file")
		}
		return resolved, nil
	}
	return "", errors.New("ansible-playbook is required in a trusted controller executable directory")
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
		if strings.Contains(line, "[ERROR]:") || strings.Contains(line, "ERROR!") || strings.Contains(line, "fatal:") || strings.Contains(line, "FAILED!") || strings.Contains(line, "unreachable=") || strings.Contains(line, "no hosts matched") {
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
