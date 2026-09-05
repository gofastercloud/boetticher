package model

import "strings"

// VPNHealthCheck is one fixed first-party observation collected by Pulse.
type VPNHealthCheck struct {
	ID      string
	Module  string
	Name    string
	Enabled bool
}

func VPNHealthChecks(airvpn, tailnet bool) []VPNHealthCheck {
	result := []VPNHealthCheck{}
	for _, module := range []struct {
		name    string
		enabled bool
		checks  []string
	}{
		{"airvpn", airvpn, []string{"service", "handshake", "forwarding", "kill-switch"}},
		{"tailnet-router", tailnet, []string{"service", "backend", "online", "advertised-route", "approved-route"}},
	} {
		for _, check := range module.checks {
			result = append(result, VPNHealthCheck{ID: "boetticher_" + strings.ReplaceAll(module.name, "-", "_") + "_" + strings.ReplaceAll(check, "-", "_"), Module: module.name, Name: check, Enabled: module.enabled})
		}
	}
	return result
}
