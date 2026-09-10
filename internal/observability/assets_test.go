package observability

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestProviderAssetsPinnedAndLoopbackOnly(t *testing.T) {
	var catalog map[string]struct{ Version, URL, SHA256 string }
	b, err := os.ReadFile(filepath.Join("assets", "catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &catalog); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"victorialogs", "victoriametrics", "grafana", "gatus", "victorialogs-datasource"} {
		v, ok := catalog[name]
		if !ok || v.Version == "" || len(v.SHA256) != 64 || !strings.HasPrefix(v.URL, "https://") {
			t.Fatalf("invalid pin %s: %#v", name, v)
		}
	}
	for _, unit := range []string{"victorialogs.service", "victoriametrics.service", "grafana.service", "gatus.service", "bifrost.service", "caddy.service"} {
		b, err := os.ReadFile(filepath.Join("assets", unit))
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		if !strings.Contains(s, "User=") || !strings.Contains(s, "NoNewPrivileges=yes") {
			t.Fatalf("%s lacks service hardening", unit)
		}
		if unit != "caddy.service" && !strings.Contains(s, "127.0.0.1") {
			t.Fatalf("%s is not loopback scoped", unit)
		}
	}
}

func TestMediaDashboardUsesPinnedNodeExporterAndGatusSeries(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("assets", "grafana-media.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"node_cpu_seconds_total", "node_memory_MemAvailable_bytes", "node_memory_MemTotal_bytes", "node_filesystem_avail_bytes", "node_filesystem_size_bytes", "node_network_receive_bytes_total", "node_network_transmit_bytes_total", "gatus_results_endpoint_success", "gatus_results_duration_seconds", "gatus_results_total", "boetticher-media", "lab-media-01"} {
		if !strings.Contains(string(data), required) {
			t.Errorf("media dashboard missing %q", required)
		}
	}
	gatus, err := os.ReadFile(filepath.Join("assets", "gatus.config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(gatus), "metrics: true") {
		t.Fatal("Gatus metrics are not enabled")
	}
}

func TestHolmesPayloadIsPinnedAndOnlyUsesLocalEvidenceProviders(t *testing.T) {
	root := filepath.Join("..", "..", "controller", "observability", "holmes")
	runner, err := os.ReadFile(filepath.Join(root, "holmes-runner.py"))
	if err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(filepath.Join(root, "holmes.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	lock, err := os.ReadFile(filepath.Join("..", "..", "images", "aiops", "runtime", "requirements.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(lock), "holmesgpt==0.40.0") {
		t.Fatal("Holmes dependency lock is not pinned to 0.40.0")
	}
	for _, required := range []string{"prometheus/metrics", "victorialogs", "http://127.0.0.1:8428", "http://127.0.0.1:9428"} {
		if !strings.Contains(string(config)+string(runner), required) {
			t.Errorf("Holmes payload missing %q", required)
		}
	}
}

func TestGrafanaProvisioningReferencesSharedLoopbackAndDashboardUID(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("assets", "grafana-datasource.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var provisioning struct {
		Datasources []struct {
			UID  string `yaml:"uid"`
			URL  string `yaml:"url"`
			Name string `yaml:"name"`
		} `yaml:"datasources"`
	}
	if err := yaml.Unmarshal(data, &provisioning); err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, datasource := range provisioning.Datasources {
		seen[datasource.UID] = datasource.URL
	}
	if seen["victoriametrics"] != "http://127.0.0.1:8428" || seen["victorialogs"] != "http://127.0.0.1:9428" {
		t.Fatalf("datasource routes = %#v", seen)
	}
	dashboard, err := os.ReadFile(filepath.Join("assets", "grafana-overview.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		UID    string `json:"uid"`
		Panels []struct {
			Datasource struct {
				UID string `json:"uid"`
			} `json:"datasource"`
		} `json:"panels"`
	}
	if err := json.Unmarshal(dashboard, &document); err != nil {
		t.Fatal(err)
	}
	if document.UID != "boetticher-observability" || len(document.Panels) == 0 {
		t.Fatalf("dashboard identity = %#v", document)
	}
	for _, panel := range document.Panels {
		if panel.Datasource.UID != "victoriametrics" && panel.Datasource.UID != "victorialogs" {
			t.Fatalf("dashboard panel references unknown datasource UID %q", panel.Datasource.UID)
		}
	}
}

func TestOperatorDashboardsAndGatusUseManagedObservabilitySources(t *testing.T) {
	dashboards := map[string]string{
		"grafana-overview.json":             "Lab Overview",
		"grafana-host-resources.json":       "Host and Guest Resources",
		"grafana-service-logs.json":         "Service Logs",
		"grafana-observability-health.json": "Observability Health",
	}
	for name, title := range dashboards {
		data, err := os.ReadFile(filepath.Join("assets", name))
		if err != nil {
			t.Fatal(err)
		}
		var dashboard struct {
			Title  string `json:"title"`
			Panels []struct {
				Targets []struct {
					Expr string `json:"expr"`
				} `json:"targets"`
			} `json:"panels"`
		}
		if err := json.Unmarshal(data, &dashboard); err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
		if dashboard.Title != title || len(dashboard.Panels) == 0 {
			t.Fatalf("dashboard %s title/panels = %q/%d", name, dashboard.Title, len(dashboard.Panels))
		}
		if name != "grafana-service-logs.json" && !strings.Contains(string(data), "boetticher_host") {
			t.Errorf("dashboard %s lacks managed node exporter labels", name)
		}
	}
	logsDashboard, err := os.ReadFile(filepath.Join("assets", "grafana-service-logs.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"_HOSTNAME", "_SYSTEMD_UNIT", "SYSLOG_IDENTIFIER"} {
		if !strings.Contains(string(logsDashboard), field) {
			t.Errorf("service logs dashboard lacks journald field %s", field)
		}
	}
	gatus, err := os.ReadFile(filepath.Join("assets", "gatus.config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"victoriametrics", "victorialogs", "grafana", "bifrost", "gatus", "127.0.0.1:8428/health", "127.0.0.1:9428/health", "127.0.0.1:4000/health"} {
		if !strings.Contains(string(gatus), required) {
			t.Errorf("Gatus configuration missing %q", required)
		}
	}
	alerts, err := os.ReadFile(filepath.Join("assets", "grafana-alerting.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"boetticher-host-unreachable", "boetticher-disk-pressure", "boetticher-missing-collection", "datasourceUid: victoriametrics", "boetticher_host"} {
		if !strings.Contains(string(alerts), required) {
			t.Errorf("Grafana alerting configuration missing %q", required)
		}
	}
	if strings.Count(string(alerts), "expression: A") != 3 || strings.Count(string(alerts), "expression: B") != 3 {
		t.Fatalf("Grafana alerts do not reduce time series before threshold evaluation")
	}
}

func TestOptionalPushoverWiringIsInertUntilEnabled(t *testing.T) {
	installer, err := os.ReadFile(filepath.Join("..", "..", "scripts", "install-observability-providers.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(installer)
	for _, required := range []string{"pushover_enabled", "public_domain", "caddy-observability", "caddy-status", "caddy-metrics", "install_optional_pushover_dropin", "contactPoints:", "receivers:", "type: pushover", "priority: \"$pushover_priority\"", "userKey:", "apiToken:", "application-token:", "send-on-resolved: false", "Pushover credentials are missing"} {
		if !strings.Contains(text, required) {
			t.Errorf("optional Pushover wiring missing %q", required)
		}
	}
	if strings.Contains(text, "secure_settings:") {
		t.Fatal("Grafana Pushover provisioning retained the legacy secure_settings schema")
	}
	for _, service := range []string{"assets/grafana.service", "assets/gatus.service"} {
		data, readErr := os.ReadFile(service)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if strings.Contains(string(data), "LoadCredential=pushover-credentials") {
			t.Fatalf("%s requires a Pushover credential while the contact is disabled", service)
		}
		if !strings.Contains(string(data), "read -r BOETTICHER_PUSHOVER_USER BOETTICHER_PUSHOVER_TOKEN < /run/credentials/") || !strings.Contains(string(data), "|| :;") {
			t.Fatalf("%s does not tolerate a valid credential file without a trailing newline", service)
		}
	}
	alerting, readErr := os.ReadFile("assets/grafana-alerting.yaml")
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, required := range []string{"groups:", "uid: boetticher-host-unreachable", "uid: boetticher-disk-pressure", "uid: boetticher-missing-collection", "deleteContactPoints:", "uid: boetticher-pushover"} {
		if !strings.Contains(string(alerting), required) {
			t.Errorf("disabled Grafana provisioning is missing expected owned state %q", required)
		}
	}
	if strings.Contains(string(alerting), "deleteRules:") {
		t.Fatal("disabled Grafana provisioning would delete monitoring alert rules")
	}
	if strings.Contains(string(alerting), "notification_settings:") || strings.Contains(string(alerting), "name: boetticher-pushover") {
		t.Fatal("disabled Grafana provisioning retained an active Pushover route")
	}
}
