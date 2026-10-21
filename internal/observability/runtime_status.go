package observability

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// ServiceCheckTimeoutSeconds bounds each in-guest unit query and each
// loopback health request independently of the caller's overall budget.
const ServiceCheckTimeoutSeconds = 5

const serviceCheckMarker = "boetticher-service-check"

// providerHealthURLs are the loopback health routes owned by each provider.
// caddy.service is checked through its admin socket instead.
var providerHealthURLs = map[string]string{
	"victorialogs.service":         "http://127.0.0.1:9428/health",
	"victoriametrics.service":      "http://127.0.0.1:8428/health",
	"grafana.service":              "http://127.0.0.1:3000/api/health",
	"gatus.service":                "http://127.0.0.1:8080/health",
	"bifrost.service":              "http://127.0.0.1:4000/health",
	"boetticher-incidentd.service": "http://127.0.0.1:8091/health",
	"caddy.service":                "http://unix/config/",
}

func providerHealthCurl(service string) (string, bool) {
	path, ok := providerHealthURLs[service]
	if !ok {
		return "", false
	}
	timeout := strconv.Itoa(ServiceCheckTimeoutSeconds)
	if service == "caddy.service" {
		return "curl --fail --silent --show-error --max-time " + timeout + " --unix-socket /run/caddy/admin.sock http://unix/config/", true
	}
	return "curl --fail --silent --show-error --max-time " + timeout + " " + shellQuoteValue(path), true
}

// CheckError names the read-only check that failed so callers can tell a
// spent budget or transport failure apart from an observed unhealthy result.
type CheckError struct {
	Check string
	Err   error
}

func (e *CheckError) Error() string { return e.Check + ": " + e.Err.Error() }
func (e *CheckError) Unwrap() error { return e.Err }

// ServiceHealth is one provider's observed unit state and loopback endpoint.
// Endpoint is "healthy", a failure detail, or empty when the unit was not
// active and the endpoint was therefore not probed.
type ServiceHealth struct {
	Service  string
	Unit     string
	Endpoint string
}

// UnitActive reports whether the observed unit state is exactly active.
func (h ServiceHealth) UnitActive() bool { return h.Unit == "active" }

// Healthy reports an active unit with a healthy loopback endpoint.
func (h ServiceHealth) Healthy() bool { return h.UnitActive() && h.Endpoint == "healthy" }

// RuntimeObservation is the bounded read-only view used by status and plan.
type RuntimeObservation struct {
	State    string
	Running  bool
	Services []ServiceHealth
}

// ObserveRuntime verifies guest ownership once, reads the guest state, and,
// when the guest is running, checks every listed provider in one bounded
// guest command. Each unit query and health request carries its own timeout
// and they run concurrently, so the command takes about one check timeout
// regardless of how many providers are listed. It performs no mutation.
func (c HostClient) ObserveRuntime(ctx context.Context, b Binding, services []string) (RuntimeObservation, error) {
	script, err := serviceChecksScript(services)
	if err != nil {
		return RuntimeObservation{}, err
	}
	if _, err := c.GuestConfig(ctx, b); err != nil {
		return RuntimeObservation{}, &CheckError{Check: fmt.Sprintf("verify guest %d ownership", b.VMID), Err: err}
	}
	r, err := c.Transport.Run(ctx, fmt.Sprintf("pct status %d", b.VMID))
	if err != nil {
		return RuntimeObservation{}, &CheckError{Check: fmt.Sprintf("read guest %d state", b.VMID), Err: err}
	}
	observation := RuntimeObservation{State: strings.TrimSpace(string(r.Stdout))}
	observation.Running = strings.Contains(strings.ToLower(observation.State), "running")
	if !observation.Running || len(services) == 0 {
		return observation, nil
	}
	check := "check services " + strings.Join(services, ", ")
	r, err = c.Transport.Run(ctx, fmt.Sprintf("pct exec %d -- sh -c %s", b.VMID, shellQuoteValue(script)))
	if err != nil {
		return RuntimeObservation{}, &CheckError{Check: check, Err: err}
	}
	observation.Services, err = parseServiceChecks(string(r.Stdout), services)
	if err != nil {
		return RuntimeObservation{}, &CheckError{Check: check, Err: err}
	}
	return observation, nil
}

// serviceChecksScript emits one tab-separated result line per service. Each
// line is a single short write, so concurrent jobs cannot interleave within it.
// The script always exits zero once it has run so that an unhealthy provider
// is reported as a result rather than a transport failure.
func serviceChecksScript(services []string) (string, error) {
	seen := map[string]bool{}
	var script strings.Builder
	timeout := strconv.Itoa(ServiceCheckTimeoutSeconds)
	for _, service := range services {
		curl, ok := providerHealthCurl(service)
		if !ok {
			return "", fmt.Errorf("unknown observability provider %s", service)
		}
		if seen[service] {
			return "", fmt.Errorf("duplicate observability provider %s", service)
		}
		seen[service] = true
		quoted := shellQuoteValue(service)
		fmt.Fprintf(&script, "( u=$(timeout %s systemctl is-active %s 2>/dev/null); rc=$?; if [ \"$rc\" -eq 124 ]; then u=check-timed-out; fi; [ -n \"$u\" ] || u=unknown; h=; if [ \"$u\" = active ]; then %s >/dev/null 2>&1; rc=$?; if [ \"$rc\" -eq 0 ]; then h=healthy; else h=curl-$rc; fi; fi; printf '%s\\t%%s\\t%%s\\t%%s\\n' %s \"$u\" \"$h\" ) &\n", timeout, quoted, curl, serviceCheckMarker, quoted)
	}
	script.WriteString("wait\nexit 0\n")
	return script.String(), nil
}

func parseServiceChecks(raw string, services []string) ([]ServiceHealth, error) {
	results := map[string]ServiceHealth{}
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(fields) != 4 || fields[0] != serviceCheckMarker {
			continue
		}
		if _, duplicate := results[fields[1]]; duplicate {
			return nil, fmt.Errorf("guest returned duplicate result for %s", fields[1])
		}
		unit := strings.TrimSpace(fields[2])
		if unit == "" || strings.ContainsAny(unit, " \t") {
			unit = "unknown"
		}
		results[fields[1]] = ServiceHealth{Service: fields[1], Unit: unit, Endpoint: endpointDetail(strings.TrimSpace(fields[3]))}
	}
	ordered := make([]ServiceHealth, 0, len(services))
	for _, service := range services {
		result, ok := results[service]
		if !ok {
			return nil, fmt.Errorf("guest returned no result for %s", service)
		}
		ordered = append(ordered, result)
	}
	return ordered, nil
}

func endpointDetail(raw string) string {
	switch raw {
	case "", "healthy":
		return raw
	case "curl-7":
		return "connection refused"
	case "curl-22":
		return "HTTP error response"
	case "curl-28":
		return fmt.Sprintf("no response within %ds", ServiceCheckTimeoutSeconds)
	}
	if code, ok := strings.CutPrefix(raw, "curl-"); ok {
		if _, err := strconv.Atoi(code); err == nil {
			return "curl exit " + code
		}
	}
	return "unrecognised result"
}
