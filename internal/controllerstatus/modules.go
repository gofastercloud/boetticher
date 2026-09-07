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
		DHCPNTP: CheckResult{Detail: "DHCP/DDNS/NTP capability is not configured"},
		DNS:     CheckResult{Detail: "DNS capability is not configured"},
	}
	if c.FirewallCommand != nil {
		status.Firewall = c.FirewallCommand(ctx)
		return status
	}
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
		status.Firewall = CheckResult{Configured: true, Healthy: true, Detail: "firewall capability status is healthy"}
	} else {
		status.Firewall = CheckResult{Configured: true, Detail: "firewall capability status is not healthy"}
	}
	return status
}

func moduleComponent(result CheckResult) Component {
	if !result.Configured {
		return Component{State: Off, Detail: result.Detail}
	}
	if result.Healthy {
		return Component{State: Healthy, Detail: result.Detail}
	}
	return Component{State: Failed, Detail: result.Detail}
}
