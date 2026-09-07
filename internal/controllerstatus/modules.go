package controllerstatus

import (
	"context"
	"errors"
	"os"
	"time"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"github.com/gofastercloud/boetticher/internal/firewallmodule"
)

// ModuleStatus is the small coarse display projection for network services.
// It is operational status only; qualification remains a separate concern.
type ModuleStatus struct {
	Firewall CheckResult
	DHCPNTP  CheckResult
	DNS      CheckResult
}

// ModuleChecker checks the firewall provider through the existing strict Host
// transport. DHCP/DDNS/NTP and DNS remain explicit red placeholders until
// their capabilities are implemented.
type ModuleChecker struct {
	LoadConfig func() (controllerhost.LabConfig, error)
	Transport  func(controllerhost.LabConfig) (controllerhost.Transport, error)
	Run        func(context.Context, controllerhost.Transport, string) (controllerhost.Result, error)
}

func (c ModuleChecker) Check(ctx context.Context) ModuleStatus {
	status := ModuleStatus{
		DHCPNTP: CheckResult{Configured: true, Detail: "DHCP/DDNS/NTP capability is not implemented"},
		DNS:     CheckResult{Configured: true, Detail: "DNS capability is not implemented"},
	}
	load := c.LoadConfig
	if load == nil {
		load = controllerhost.LoadConfig
	}
	config, err := load()
	if errors.Is(err, os.ErrNotExist) {
		status.Firewall.Detail = "Host not enrolled"
		return status
	}
	if err != nil {
		status.Firewall.Configured = true
		status.Firewall.Detail = "Host configuration cannot be read"
		return status
	}
	if config.Proxmox.Node == "" {
		status.Firewall.Detail = "Host not enrolled"
		return status
	}
	transportFor := c.Transport
	if transportFor == nil {
		transportFor = controllerhost.TransportFor
	}
	transport, err := transportFor(config)
	if err != nil {
		status.Firewall.Configured = true
		status.Firewall.Detail = "Host transport configuration is invalid"
		return status
	}
	transport.Timeout = 5 * time.Second
	run := c.Run
	if run == nil {
		run = func(ctx context.Context, transport controllerhost.Transport, command string) (controllerhost.Result, error) {
			return transport.Run(ctx, command)
		}
	}
	if _, err := run(ctx, transport, firewallmodule.ProviderHealthCommand()); err != nil {
		status.Firewall.Configured = true
		status.Firewall.Detail = "firewall provider health check failed"
		return status
	}
	status.Firewall = CheckResult{Configured: true, Healthy: true, Detail: "firewall provider is running with the expected identity"}
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
