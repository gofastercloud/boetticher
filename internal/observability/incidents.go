package observability

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
)

const maxIncidentResponseBytes = 512 * 1024

// GrafanaIncident reads the private incident API from inside the owned guest.
// The browser path is authenticated by Caddy's Grafana forward-auth check;
// the Controller path uses only the local Holmes caller credential.
func (c HostClient) GrafanaIncident(ctx context.Context, b Binding, id string) (string, error) {
	if !safeIncidentID(id) {
		return "", errors.New("Grafana incident id is invalid")
	}
	return c.grafanaIncidentRequest(ctx, b, "GET", "/api/incidents/"+id, nil)
}

// GrafanaIncidents returns the bounded private incident list.  The name is
// retained for CLI compatibility; persistence is owned by the incident
// service, while Grafana supplies the browser authentication boundary.
func (c HostClient) GrafanaIncidents(ctx context.Context, b Binding) (string, error) {
	return c.grafanaIncidentRequest(ctx, b, "GET", "/api/incidents", nil)
}

// GrafanaIncidentInvestigation is deliberately read-only.  It fetches the
// incident and leaves any model investigation to the explicit Holmes command.
func (c HostClient) GrafanaIncidentInvestigation(ctx context.Context, b Binding, id string) (string, error) {
	if !safeIncidentID(id) {
		return "", errors.New("Grafana incident id is invalid")
	}
	return c.grafanaIncidentRequest(ctx, b, "POST", "/api/incidents/"+id+"/investigate", nil)
}

func (c HostClient) grafanaIncidentRequest(ctx context.Context, b Binding, method, endpoint string, body io.Reader) (string, error) {
	if (method != "GET" && method != "POST") || (endpoint != "/api/incidents" && !strings.HasPrefix(endpoint, "/api/incidents/")) {
		return "", errors.New("unsupported Grafana incident endpoint")
	}
	// The guest-side script reads the systemd-projected local caller credential.
	// No secret value is interpolated into this command or returned by the helper.
	script := `import json,sys,urllib.request
path="/var/lib/boetticher/credentials/holmes-client-token.cred"
token=open(path,encoding="utf-8").read().strip()
request=urllib.request.Request("http://127.0.0.1:8091"+sys.argv[1],method=sys.argv[2],headers={"Authorization":"Bearer "+token})
with urllib.request.urlopen(request,timeout=15) as response:
 data=response.read(524289)
 if len(data)>524288: raise SystemExit("Grafana incident response exceeded its bound")
 sys.stdout.buffer.write(data)`
	command := fmt.Sprintf("pct exec %d -- python3 -c %s %s %s", b.VMID, shellQuoteValue(script), shellQuoteValue(endpoint), shellQuoteValue(method))
	runner, ok := c.Transport.(Runner)
	if !ok {
		return "", errors.New("observability transport is unavailable")
	}
	result, err := runner.Run(ctx, command)
	if err != nil {
		return "", fmt.Errorf("Grafana incident request failed: %w", err)
	}
	if len(result.Stdout) == 0 || len(result.Stdout) > maxIncidentResponseBytes {
		return "", errors.New("Grafana incident response is empty or exceeds its bound")
	}
	return strings.TrimSpace(string(result.Stdout)), nil
}

func safeIncidentID(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-' || char == '_') {
			return false
		}
	}
	return true
}
