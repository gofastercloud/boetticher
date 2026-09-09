package controllerstatus

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"
)

// ModuleStatus is the small coarse display projection for network services.
// It is operational status only; qualification remains a separate concern.
type ModuleStatus struct {
	Firewall CheckResult
	VPN      CheckResult
	DHCPNTP  CheckResult
	DNS      CheckResult
	Tailnet  CheckResult
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
		VPN:     CheckResult{State: Off, Detail: "VPN capability not configured"},
		DHCPNTP: CheckResult{State: Off, Detail: "DHCP/NTP capability not configured"},
		DNS:     CheckResult{State: Off, Detail: "DNS capability not configured"},
		Tailnet: CheckResult{State: Off, Detail: "Tailnet capability not configured"},
	}
	// A test or embedding may provide only the native firewall check. Preserve
	// that narrow mode without attempting the default CLI for other modules.
	if c.FirewallCommand != nil && c.RunCommand == nil {
		status.Firewall = c.FirewallCommand(ctx)
		return status
	}

	type result struct {
		component string
		value     CheckResult
	}
	results := make(chan result, 5)
	var workers sync.WaitGroup
	start := func(component string, check func(context.Context) CheckResult) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			// Every check starts together and may use the complete refresh budget.
			// Parallelism prevents a slow provider from consuming another check's
			// budget; a shorter per-check timeout would reject valid native checks.
			checkCtx, cancel := context.WithTimeout(ctx, moduleCheckTimeout)
			defer cancel()
			results <- result{component: component, value: check(checkCtx)}
		}()
	}
	start("firewall", func(checkCtx context.Context) CheckResult {
		if c.FirewallCommand != nil {
			return c.FirewallCommand(checkCtx)
		}
		return c.checkCapability(checkCtx, "module", "firewall", "status", "Firewall")
	})
	start("dhcp", func(checkCtx context.Context) CheckResult {
		return c.checkCapability(checkCtx, "module", "dhcp", "status", "DHCP/NTP")
	})
	start("dns", func(checkCtx context.Context) CheckResult {
		return c.checkCapability(checkCtx, "module", "dns", "status", "DNS")
	})
	start("vpn", c.checkVPN)
	start("tailnet", c.checkTailnet)
	workers.Wait()
	close(results)
	for item := range results {
		switch item.component {
		case "firewall":
			status.Firewall = item.value
		case "dhcp":
			status.DHCPNTP = item.value
		case "dns":
			status.DNS = item.value
		case "vpn":
			status.VPN = item.value
		case "tailnet":
			status.Tailnet = item.value
		}
	}
	return status
}

func (c ModuleChecker) checkVPN(ctx context.Context) CheckResult {
	run := c.RunCommand
	if run == nil {
		run = defaultCommand
	}
	path := c.CommandPath
	if path == "" {
		path = "/usr/local/bin/boetticher"
	}
	output, err := run(ctx, path, "module", "vpn", "status")
	text := strings.TrimSpace(string(output))
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "VPN: OFF" && err == nil:
			return CheckResult{State: Off, Detail: "VPN capability not configured"}
		case line == "VPN: CONNECTED" && err == nil:
			return CheckResult{Configured: true, Healthy: true, State: Healthy, Detail: "VPN connection is available; enforcement is reported separately"}
		case strings.HasPrefix(line, "VPN: "):
			if line == "VPN: CHECKING" {
				return CheckResult{Configured: true, State: Attention, Detail: "VPN configuration has a pending additive intent"}
			}
			return CheckResult{Configured: true, State: Failed, Detail: "VPN status is not healthy"}
		}
	}
	if err != nil {
		return CheckResult{Configured: true, State: Failed, Detail: "VPN status check failed"}
	}
	return CheckResult{Configured: true, State: Failed, Detail: "VPN status evidence is missing or malformed"}
}

func (c ModuleChecker) checkTailnet(ctx context.Context) CheckResult {
	run := c.RunCommand
	if run == nil {
		run = defaultCommand
	}
	path := c.CommandPath
	if path == "" {
		path = "/usr/local/bin/boetticher"
	}
	output, err := run(ctx, path, "module", "tailnet", "status", "--json")
	return parseTailnetResult(output, err, time.Now().UTC())
}

type tailnetStatusJSON struct {
	Configured *bool     `json:"configured"`
	State      State     `json:"state"`
	Detail     string    `json:"detail"`
	ObservedAt time.Time `json:"observed_at"`
}

func parseTailnetResult(output []byte, commandErr error, now time.Time) CheckResult {
	var value tailnetStatusJSON
	if err := json.Unmarshal(output, &value); err != nil || value.Detail == "" || value.ObservedAt.IsZero() || value.ObservedAt.After(now.Add(5*time.Second)) || now.Sub(value.ObservedAt) > 45*time.Second {
		return CheckResult{Configured: true, State: Failed, Detail: "Tailnet status evidence is missing, malformed, or stale", ObservedAt: value.ObservedAt}
	}
	if value.State != Off && value.State != Checking && value.State != Attention && value.State != Failed && value.State != Healthy {
		return CheckResult{Configured: true, State: Failed, Detail: "Tailnet status evidence has an unknown state", ObservedAt: value.ObservedAt}
	}
	if value.Configured == nil {
		return CheckResult{Configured: true, State: Failed, Detail: "Tailnet status evidence is missing configured state", ObservedAt: value.ObservedAt}
	}
	if !*value.Configured && value.State != Off {
		return CheckResult{Configured: true, State: Failed, Detail: "Tailnet status evidence has an invalid configured state", ObservedAt: value.ObservedAt}
	}
	if *value.Configured && value.State == Off {
		return CheckResult{Configured: true, State: Failed, Detail: "Tailnet configured state cannot be off", ObservedAt: value.ObservedAt}
	}
	if value.State == Healthy && (!*value.Configured || commandErr != nil) {
		return CheckResult{Configured: true, State: Failed, Detail: "Tailnet healthy status was not returned by a successful command", ObservedAt: value.ObservedAt}
	}
	return CheckResult{Configured: *value.Configured, Healthy: value.State == Healthy, State: value.State, Detail: value.Detail, ObservedAt: value.ObservedAt}
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
	if strings.Contains(text, ": CHECKING") {
		return CheckResult{Configured: true, State: Attention, Detail: label + " has pending additive intent"}
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
