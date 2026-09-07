package controllerstatus

import (
	"context"
	"strings"
)

// ModuleStatus is the small coarse display projection for network services.
// It is operational status only; qualification remains a separate concern.
type ModuleStatus struct {
	Firewall CheckResult
	DHCPNTP  CheckResult
	DNS      CheckResult
}

// ModuleChecker reuses the native firewall capability status command. This
// keeps the display from growing a second provider-health implementation.
type ModuleChecker struct {
	FirewallCommand func(context.Context) CheckResult
	CommandPath     string
	RunCommand      CommandRunner
}

func (c ModuleChecker) Check(ctx context.Context) ModuleStatus {
	status := ModuleStatus{
		DHCPNTP: CheckResult{State: Off, Detail: "DHCP/NTP capability not configured"},
		DNS:     CheckResult{State: Off, Detail: "DNS capability not configured"},
	}
	if c.FirewallCommand != nil {
		status.Firewall = c.FirewallCommand(ctx)
		return status
	}
	status.DHCPNTP = c.checkCapability(ctx, "module", "dhcp", "status", "DHCP/NTP")
	status.DNS = c.checkCapability(ctx, "module", "dns", "status", "DNS")
	run := c.RunCommand
	if run == nil {
		run = defaultCommand
	}
	path := c.CommandPath
	if path == "" {
		path = "/usr/local/bin/boetticher"
	}
	output, err := run(ctx, path, "module", "firewall", "status")
	if err != nil {
		status.Firewall = CheckResult{Configured: true, Detail: "firewall capability status check failed"}
		return status
	}
	if strings.Contains(string(output), "Firewall: PASS") {
		status.Firewall = CheckResult{Configured: true, Healthy: true, State: Healthy, Detail: "firewall capability status is healthy"}
	} else {
		status.Firewall = CheckResult{Configured: true, State: Failed, Detail: "firewall capability status is not healthy"}
	}
	return status
}

func (c ModuleChecker) checkCapability(ctx context.Context, args ...string) CheckResult {
	label := args[len(args)-1]
	commandArgs := args[:len(args)-1]
	run := c.RunCommand
	if run == nil {
		run = defaultCommand
	}
	path := c.CommandPath
	if path == "" {
		path = "/usr/local/bin/boetticher"
	}
	output, err := run(ctx, path, commandArgs...)
	text := strings.TrimSpace(string(output))
	if strings.Contains(strings.ToLower(text), "not configured") {
		return CheckResult{State: Off, Detail: label + " capability not configured"}
	}
	if err != nil {
		return CheckResult{Configured: true, State: Failed, Detail: label + " capability status check failed"}
	}
	if strings.Contains(text, ": PASS") {
		return CheckResult{Configured: true, Healthy: true, State: Healthy, Detail: label + " capability is healthy"}
	}
	return CheckResult{Configured: true, State: Failed, Detail: label + " capability is not healthy"}
}

func moduleComponent(result CheckResult) Component {
	if !result.Configured {
		return Component{State: Off, Detail: result.Detail}
	}
	if result.State != "" {
		return Component{State: result.State, Detail: result.Detail}
	}
	if result.Healthy {
		return Component{State: Healthy, Detail: result.Detail}
	}
	return Component{State: Failed, Detail: result.Detail}
}

func debouncedModuleComponent(debouncer *Debouncer, result CheckResult) Component {
	if !result.Configured {
		return moduleComponent(result)
	}
	if result.State == Attention || result.State == Checking {
		return moduleComponent(result)
	}
	return debouncer.Update(result.Healthy, result.Detail)
}
