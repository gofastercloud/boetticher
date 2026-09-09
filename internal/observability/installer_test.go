package observability

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeExecutable(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
}

func installerPath(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate installer test source")
	}
	return filepath.Join(filepath.Dir(source), "..", "..", "scripts", "install-observability-providers.sh")
}

func TestProviderInstallerStagesGatusAssetsAndOrdersAccountBeforeOwnership(t *testing.T) {
	root := t.TempDir()
	fakeBin := t.TempDir()
	logPath := filepath.Join(root, "calls.log")
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "passwd"), []byte("root:x:0:0:root:/root:/bin/sh\n"), 0644); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, filepath.Join(fakeBin, "useradd"), "#!/bin/sh\nset -eu\nroot=/\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = --root ]; then root=$2; shift 2; continue; fi\n  account=$1\n  shift\ndone\nprintf 'useradd %s\\n' \"$account\" >> \"$TEST_CALL_LOG\"\nprintf '%s:x:2200:2200::/var/lib/%s:/usr/sbin/nologin\\n' \"$account\" \"$account\" >> \"$root/etc/passwd\"\n")
	writeExecutable(t, filepath.Join(fakeBin, "chown"), "#!/bin/sh\nprintf 'chown %s\\n' \"$*\" >> \"$TEST_CALL_LOG\"\n")
	writeExecutable(t, filepath.Join(fakeBin, "systemctl"), "#!/bin/sh\nprintf 'systemctl %s\\n' \"$*\" >> \"$TEST_CALL_LOG\"\n")
	gatusBinary := filepath.Join(t.TempDir(), "gatus")
	if err := os.WriteFile(gatusBinary, []byte("gatus-test-binary"), 0755); err != nil {
		t.Fatal(err)
	}
	env := append([]string(nil), os.Environ()...)
	env = append(env,
		"PATH="+fakeBin+":"+os.Getenv("PATH"),
		"TEST_CALL_LOG="+logPath,
		"BOETTICHER_OBSERVABILITY_ASSETS="+filepath.Join(filepath.Dir(installerPath(t)), "..", "internal", "observability", "assets"),
		"BOETTICHER_OBSERVABILITY_GATUS_BINARY="+gatusBinary,
		"BOETTICHER_OBSERVABILITY_PUBLIC_DOMAIN=davebarton.cc",
		"BOETTICHER_OBSERVABILITY_METRICS_CONTROLLER=10.10.20.10",
		"BOETTICHER_OBSERVABILITY_METRICS_HOST=10.10.99.5",
	)
	cmd := exec.Command("sh", installerPath(t), "gatus", "--root", root)
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("installer failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "provider gatus: PASS (staged and enabled; health NOT TESTED)") {
		t.Fatalf("installer did not report PASS: %s", output)
	}
	installed, err := os.ReadFile(filepath.Join(root, "usr", "local", "bin", "gatus"))
	if err != nil || string(installed) != "gatus-test-binary" {
		t.Fatalf("installed Gatus binary = %q, err=%v", installed, err)
	}
	config, err := os.ReadFile(filepath.Join(root, "etc", "boetticher", "gatus", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"https://observability.davebarton.cc/api/health", "https://status.davebarton.cc/health", "https://metrics.davebarton.cc/lab-monitor-01/metrics", "query-name: observability.davebarton.cc", "tcp://10.10.99.5:9100", "tcp://10.10.20.10:9100", "[DNS_RCODE] == NOERROR", "[CONNECTED] == true", "[STATUS] == 401"} {
		if !strings.Contains(string(config), required) {
			t.Errorf("Gatus public outcome check missing %q: %s", required, config)
		}
	}
	for _, path := range []string{"etc/boetticher/gatus/config.yaml", "etc/systemd/system/gatus.service"} {
		if _, err := os.Stat(filepath.Join(root, path)); err != nil {
			t.Fatal(err)
		}
	}
	calls, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	callText := string(calls)
	if strings.Index(callText, "useradd gatus") < 0 || strings.Index(callText, "chown") < 0 || strings.Index(callText, "useradd gatus") > strings.Index(callText, "chown") {
		t.Fatalf("service account was not created before ownership changes: %s", callText)
	}
	if !strings.Contains(callText, "systemctl --root="+root+" enable gatus.service") {
		t.Fatalf("staged unit was not enabled: %s", callText)
	}
}

func TestProviderInstallerStagesOptionalPushoverGatusAlerting(t *testing.T) {
	root := t.TempDir()
	fakeBin := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "passwd"), []byte("root:x:0:0:root:/root:/bin/sh\n"), 0644); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, filepath.Join(fakeBin, "useradd"), "#!/bin/sh\nset -eu\nroot=/\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = --root ]; then root=$2; shift 2; continue; fi\n  account=$1; shift\ndone\nprintf '%s:x:2200:2200::/var/lib/%s:/usr/sbin/nologin\\n' \"$account\" \"$account\" >> \"$root/etc/passwd\"\n")
	writeExecutable(t, filepath.Join(fakeBin, "chown"), "#!/bin/sh\nexit 0\n")
	writeExecutable(t, filepath.Join(fakeBin, "systemctl"), "#!/bin/sh\nexit 0\n")
	gatusBinary := filepath.Join(t.TempDir(), "gatus")
	if err := os.WriteFile(gatusBinary, []byte("gatus-test-binary"), 0755); err != nil {
		t.Fatal(err)
	}
	credentials := filepath.Join(root, "var", "lib", "boetticher", "credentials", "pushover-credentials.cred")
	if err := os.MkdirAll(filepath.Dir(credentials), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credentials, []byte("user-key:api-token"), 0600); err != nil {
		t.Fatal(err)
	}
	env := append([]string(nil), os.Environ()...)
	env = append(env, "PATH="+fakeBin+":"+os.Getenv("PATH"), "BOETTICHER_OBSERVABILITY_ASSETS="+filepath.Join(filepath.Dir(installerPath(t)), "..", "internal", "observability", "assets"), "BOETTICHER_OBSERVABILITY_GATUS_BINARY="+gatusBinary, "BOETTICHER_OBSERVABILITY_PUSHOVER_ENABLED=true", "BOETTICHER_OBSERVABILITY_PUSHOVER_TITLE=Boetticher-alerts", "BOETTICHER_OBSERVABILITY_PUSHOVER_PRIORITY=0")
	cmd := exec.Command("sh", installerPath(t), "gatus", "--root", root)
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("optional Pushover Gatus install failed: %v\\n%s", err, output)
	}
	config, err := os.ReadFile(filepath.Join(root, "etc", "boetticher", "gatus", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"application-token: ${BOETTICHER_PUSHOVER_TOKEN}", "user-key: ${BOETTICHER_PUSHOVER_USER}", "type: pushover", "send-on-resolved: false"} {
		if !strings.Contains(string(config), required) {
			t.Errorf("Gatus Pushover config missing %q: %s", required, config)
		}
	}
	dropin, err := os.ReadFile(filepath.Join(root, "etc", "systemd", "system", "gatus.service.d", "boetticher-pushover.conf"))
	if err != nil || !strings.Contains(string(dropin), "LoadCredential=pushover-credentials") {
		t.Fatalf("Gatus Pushover credential drop-in missing: err=%v content=%s", err, dropin)
	}
	// A disable reapply removes only the owned runtime projection and restores
	// the inert base configuration. This protects against credentials or alert
	// routes remaining active after intent is disabled.
	disabledEnv := make([]string, 0, len(env)+1)
	for _, value := range env {
		if strings.HasPrefix(value, "BOETTICHER_OBSERVABILITY_PUSHOVER_ENABLED=") {
			continue
		}
		disabledEnv = append(disabledEnv, value)
	}
	disabledEnv = append(disabledEnv, "BOETTICHER_OBSERVABILITY_PUSHOVER_ENABLED=false")
	disable := exec.Command("sh", installerPath(t), "gatus", "--root", root)
	disable.Env = disabledEnv
	if output, err := disable.CombinedOutput(); err != nil {
		t.Fatalf("optional Pushover disable failed: %v\n%s", err, output)
	}
	config, err = os.ReadFile(filepath.Join(root, "etc", "boetticher", "gatus", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(config), "alerting:") || strings.Contains(string(config), "type: pushover") {
		t.Fatalf("disabled Gatus retained Pushover alerting: %s", config)
	}
	if _, err := os.Stat(filepath.Join(root, "etc", "systemd", "system", "gatus.service.d", "boetticher-pushover.conf")); !os.IsNotExist(err) {
		t.Fatalf("disabled Gatus retained Pushover credential projection: %v", err)
	}
}

func TestProviderInstallerStagesHolmesRunnerWithoutStaticService(t *testing.T) {
	root := t.TempDir()
	fakeBin := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "passwd"), []byte("root:x:0:0:root:/root:/bin/sh\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "group"), []byte("root:x:0:\ncaddy:x:2200:\n"), 0644); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, filepath.Join(fakeBin, "useradd"), "#!/bin/sh\nset -eu\nroot=/\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = --root ]; then root=$2; shift 2; continue; fi\n  account=$1; shift\ndone\nprintf '%s:x:2200:2200::/var/lib/%s:/usr/sbin/nologin\\n' \"$account\" \"$account\" >> \"$root/etc/passwd\"\n")
	writeExecutable(t, filepath.Join(fakeBin, "chown"), "#!/bin/sh\nexit 0\n")
	env := append([]string(nil), os.Environ()...)
	holmesRoot := filepath.Join(filepath.Dir(installerPath(t)), "..", "controller", "observability", "holmes")
	env = append(env, "PATH="+fakeBin+":"+os.Getenv("PATH"), "BOETTICHER_OBSERVABILITY_ASSETS="+filepath.Join(filepath.Dir(installerPath(t)), "..", "internal", "observability", "assets"), "BOETTICHER_OBSERVABILITY_HOLMES_ROOT="+holmesRoot)
	cmd := exec.Command("sh", installerPath(t), "holmes", "--root", root)
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Holmes installer failed: %v\\n%s", err, output)
	}
	if !strings.Contains(string(output), "provider holmes: PASS (staged; on-demand health NOT TESTED)") {
		t.Fatalf("Holmes installer did not report staged PASS: %s", output)
	}
	for _, path := range []string{"opt/boetticher/observability/holmes/holmes-runner.py", "opt/boetticher/observability/holmes/requirements.lock", "etc/boetticher/holmes/config.yaml"} {
		if _, err := os.Stat(filepath.Join(root, path)); err != nil {
			t.Fatalf("Holmes staged file %s is missing: %v", path, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "etc/systemd/system/boetticher-holmes-ask.service")); !os.IsNotExist(err) {
		t.Fatalf("Holmes installer created a static service: %v", err)
	}
}

func TestProviderInstallerProjectsBifrostUpstreamCredentials(t *testing.T) {
	root := t.TempDir()
	fakeBin := t.TempDir()
	assetRoot := filepath.Join(filepath.Dir(installerPath(t)), "..", "internal", "observability", "assets")
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "passwd"), []byte("root:x:0:0:root:/root:/bin/sh\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "group"), []byte("root:x:0:\nbifrost:x:2201:\n"), 0644); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, filepath.Join(fakeBin, "useradd"), "#!/bin/sh\nset -eu\nroot=/\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = --root ]; then root=$2; shift 2; continue; fi\n  account=$1; shift\ndone\nprintf '%s:x:2200:2200::/var/lib/%s:/usr/sbin/nologin\\n' \"$account\" \"$account\" >> \"$root/etc/passwd\"\n")
	writeExecutable(t, filepath.Join(fakeBin, "chown"), "#!/bin/sh\nexit 0\n")
	writeExecutable(t, filepath.Join(fakeBin, "systemctl"), "#!/bin/sh\nexit 0\n")
	binary := filepath.Join(t.TempDir(), "bifrost")
	if err := os.WriteFile(binary, []byte("bifrost-fixture"), 0755); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(t.TempDir(), "bifrost.json")
	if err := os.WriteFile(config, []byte(`{"listen":"127.0.0.1:4000","client_credential":"holmes-client-token","upstreams":[{"name":"provider","base_url":"https://provider.example","credential":"provider-key"}],"models":[{"alias":"operations","upstream":"provider","model":"model"}]}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "var", "lib", "boetticher", "credentials"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "var", "lib", "boetticher", "credentials", "provider-key.cred"), []byte("fixture-key"), 0600); err != nil {
		t.Fatal(err)
	}
	env := append([]string(nil), os.Environ()...)
	env = append(env, "PATH="+fakeBin+":"+os.Getenv("PATH"), "BOETTICHER_OBSERVABILITY_ASSETS="+assetRoot, "BOETTICHER_OBSERVABILITY_BIFROST_BINARY="+binary, "BOETTICHER_OBSERVABILITY_BIFROST_CONFIG="+config)
	cmd := exec.Command("sh", installerPath(t), "bifrost", "--root", root)
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Bifrost installer failed: %v\\n%s", err, output)
	}
	dropin, err := os.ReadFile(filepath.Join(root, "etc", "systemd", "system", "bifrost.service.d", "boetticher-credentials.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dropin), "LoadCredential=provider-key:/var/lib/boetticher/credentials/provider-key.cred") || strings.Contains(string(dropin), "fixture-key") {
		t.Fatalf("Bifrost credential projection is unsafe: %s", dropin)
	}
	if err := os.Remove(filepath.Join(root, "var", "lib", "boetticher", "credentials", "provider-key.cred")); err != nil {
		t.Fatal(err)
	}
	secondCmd := exec.Command("sh", installerPath(t), "bifrost", "--root", root)
	secondCmd.Env = env
	second, secondErr := secondCmd.CombinedOutput()
	if secondErr == nil || !strings.Contains(string(second), "Bifrost upstream credential is missing") {
		t.Fatalf("missing Bifrost credential was not rejected before mutation: %v %s", secondErr, second)
	}
	after, err := os.ReadFile(filepath.Join(root, "etc", "systemd", "system", "bifrost.service.d", "boetticher-credentials.conf"))
	if err != nil || string(after) != string(dropin) {
		t.Fatalf("missing Bifrost credential changed owned projection: err=%v content=%s", err, after)
	}
}

func TestProviderInstallerBadChecksumDoesNotReplaceBinary(t *testing.T) {
	root := t.TempDir()
	fakeBin := t.TempDir()
	logPath := filepath.Join(root, "calls.log")
	writeExecutable(t, filepath.Join(fakeBin, "curl"), "#!/bin/sh\nset -eu\noutput=''\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = --output ]; then output=$2; shift 2; continue; fi\n  shift\ndone\nprintf 'untrusted provider bytes\\n' > \"$output\"\n")
	if err := os.MkdirAll(filepath.Join(root, "usr", "local", "bin"), 0755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(root, "usr", "local", "bin", "victoria-logs")
	if err := os.WriteFile(sentinel, []byte("previous-binary"), 0755); err != nil {
		t.Fatal(err)
	}
	env := append([]string(nil), os.Environ()...)
	env = append(env, "PATH="+fakeBin+":"+os.Getenv("PATH"), "TEST_CALL_LOG="+logPath, "BOETTICHER_OBSERVABILITY_ASSETS="+filepath.Join(filepath.Dir(installerPath(t)), "..", "internal", "observability", "assets"))
	cmd := exec.Command("sh", installerPath(t), "victorialogs", "--root", root)
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "checksum verification failed") {
		t.Fatalf("expected checksum failure, err=%v output=%s", err, output)
	}
	unchanged, err := os.ReadFile(sentinel)
	if err != nil || string(unchanged) != "previous-binary" {
		t.Fatalf("existing binary changed after checksum failure: %q, err=%v", unchanged, err)
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatalf("installer performed post-download mutations after checksum failure: %v", err)
	}
}

func TestProviderInstallerGrafanaPluginRepeatPreservesExecutableMode(t *testing.T) {
	root := t.TempDir()
	fakeBin := t.TempDir()
	assetRoot := t.TempDir()
	logPath := filepath.Join(root, "calls.log")
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "passwd"), []byte("root:x:0:0:root:/root:/bin/sh\n"), 0644); err != nil {
		t.Fatal(err)
	}
	sourceAssets := filepath.Join(filepath.Dir(installerPath(t)), "..", "internal", "observability", "assets")
	entries, err := os.ReadDir(sourceAssets)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		data, readErr := os.ReadFile(filepath.Join(sourceAssets, entry.Name()))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if writeErr := os.WriteFile(filepath.Join(assetRoot, entry.Name()), data, 0644); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	archivePath := filepath.Join(t.TempDir(), "plugin.zip")
	archiveFile, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	archiveWriter := zip.NewWriter(archiveFile)
	for _, item := range []struct {
		name string
		mode os.FileMode
		data string
	}{
		{name: "victoriametrics-logs-datasource/plugin.json", mode: 0644, data: `{"type":"datasource"}`},
		{name: "victoriametrics-logs-datasource/gpx_backend", mode: 0755, data: "backend"},
	} {
		header := &zip.FileHeader{Name: item.name, Method: zip.Deflate}
		header.SetMode(item.mode)
		writer, writeErr := archiveWriter.CreateHeader(header)
		if writeErr != nil {
			t.Fatal(writeErr)
		}
		if _, writeErr = writer.Write([]byte(item.data)); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	if err = archiveWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err = archiveFile.Close(); err != nil {
		t.Fatal(err)
	}
	pluginData, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(pluginData)
	grafanaPackage := []byte("grafana package fixture")
	grafanaDigest := sha256.Sum256(grafanaPackage)
	catalog, err := os.ReadFile(filepath.Join(assetRoot, "catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	oldDigest := "d5da774cd57e5f21688f3cda3eb5aac159353a32c4edbd8bee3af013e27cb991"
	catalogText := strings.Replace(string(catalog), oldDigest, hex.EncodeToString(digest[:]), 1)
	oldGrafanaDigest := "3ba6a81a7a4b1832791457058ce07551df94c3979f544bff4db886e638110644"
	catalog = []byte(strings.Replace(catalogText, oldGrafanaDigest, hex.EncodeToString(grafanaDigest[:]), 1))
	if err = os.WriteFile(filepath.Join(assetRoot, "catalog.json"), catalog, 0644); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, filepath.Join(fakeBin, "curl"), "#!/bin/sh\nset -eu\noutput=''\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = --output ]; then output=$2; shift 2; continue; fi\n  shift\ndone\ncase \"$output\" in\n  *victorialogs-datasource.zip*) cp \"$TEST_PLUGIN_ZIP\" \"$output\" ;;\n  *) printf 'grafana package fixture' > \"$output\" ;;\nesac\n")
	writeExecutable(t, filepath.Join(fakeBin, "useradd"), "#!/bin/sh\nset -eu\nroot=/\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = --root ]; then root=$2; shift 2; continue; fi\n  account=$1\n  shift\ndone\nprintf '%s:x:2200:2200::/var/lib/%s:/usr/sbin/nologin\\n' \"$account\" \"$account\" >> \"$root/etc/passwd\"\nprintf 'useradd %s\\n' \"$account\" >> \"$TEST_CALL_LOG\"\n")
	writeExecutable(t, filepath.Join(fakeBin, "chown"), "#!/bin/sh\nprintf 'chown %s\\n' \"$*\" >> \"$TEST_CALL_LOG\"\n")
	writeExecutable(t, filepath.Join(fakeBin, "dpkg"), "#!/bin/sh\nprintf 'dpkg %s\\n' \"$*\" >> \"$TEST_CALL_LOG\"\n")
	writeExecutable(t, filepath.Join(fakeBin, "systemctl"), "#!/bin/sh\nprintf 'systemctl %s\\n' \"$*\" >> \"$TEST_CALL_LOG\"\n")
	env := append([]string(nil), os.Environ()...)
	env = append(env, "PATH="+fakeBin+":"+os.Getenv("PATH"), "TEST_CALL_LOG="+logPath, "TEST_PLUGIN_ZIP="+archivePath, "BOETTICHER_OBSERVABILITY_ASSETS="+assetRoot)
	for run := 0; run < 2; run++ {
		cmd := exec.Command("sh", installerPath(t), "grafana", "--root", root)
		cmd.Env = env
		output, runErr := cmd.CombinedOutput()
		if runErr != nil {
			t.Fatalf("Grafana installer run %d failed: %v\n%s", run+1, runErr, output)
		}
	}
	backend := filepath.Join(root, "var", "lib", "boetticher", "observability", "state", "grafana", "plugins", "victoriametrics-logs-datasource", "gpx_backend")
	info, err := os.Stat(backend)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0755 {
		t.Fatalf("plugin executable mode = %o, want 755", info.Mode().Perm())
	}
	calls, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(calls), "dpkg ") != 2 || strings.Count(string(calls), "grafana-server.service") != 2 || strings.Contains(string(calls), "allow_loading_unsigned_plugins") {
		t.Fatalf("unexpected repeat installation calls: %s", calls)
	}
	ini, err := os.ReadFile(filepath.Join(root, "etc", "grafana", "grafana.ini"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ini), "http_addr = 127.0.0.1") {
		t.Fatalf("managed Grafana config does not pin loopback listener: %s", ini)
	}
	if !strings.Contains(string(ini), "provisioning = /etc/grafana/provisioning") {
		t.Fatalf("managed Grafana config does not point at the installed provisioning tree: %s", ini)
	}
	for _, file := range []string{
		filepath.Join(root, "etc", "grafana", "provisioning", "datasources", "boetticher.yaml"),
		filepath.Join(root, "etc", "grafana", "provisioning", "dashboards", "boetticher.yaml"),
		filepath.Join(root, "etc", "grafana", "dashboards", "boetticher-overview.json"),
	} {
		if _, err := os.Stat(file); err != nil {
			t.Fatalf("Grafana provisioning asset missing after install: %s: %v", file, err)
		}
	}
}

func TestProviderInstallerUsesCaddyFrontendAsset(t *testing.T) {
	asset, err := os.ReadFile(filepath.Join(filepath.Dir(installerPath(t)), "..", "internal", "observability", "assets", "caddy.service"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(asset)
	for _, required := range []string{"User=caddy", "RuntimeDirectory=caddy", "RuntimeDirectoryMode=0700", "LoadCredential=cloudflare-dns-token", "CLOUDFLARE_API_TOKEN", "printf \"%%s", "ProtectSystem=strict", "NoNewPrivileges=yes"} {
		if !strings.Contains(text, required) {
			t.Errorf("Caddy frontend asset is missing %q", required)
		}
	}
}

func TestProviderInstallerStagesInternalOnlyCaddyConfig(t *testing.T) {
	root := t.TempDir()
	fakeBin := t.TempDir()
	assetRoot := filepath.Join(filepath.Dir(installerPath(t)), "..", "internal", "observability", "assets")
	if err := os.MkdirAll(filepath.Join(root, "etc", "boetticher"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "passwd"), []byte("root:x:0:0:root:/root:/bin/sh\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "group"), []byte("root:x:0:\ncaddy:x:2200:\n"), 0644); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, filepath.Join(fakeBin, "useradd"), "#!/bin/sh\nset -eu\nroot=/\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = --root ]; then root=$2; shift 2; continue; fi\n  account=$1; shift\ndone\nprintf '%s:x:2200:2200::/var/lib/%s:/usr/sbin/nologin\\n' \"$account\" \"$account\" >> \"$root/etc/passwd\"\n")
	writeExecutable(t, filepath.Join(fakeBin, "chown"), "#!/bin/sh\nexit 0\n")
	writeExecutable(t, filepath.Join(fakeBin, "systemctl"), "#!/bin/sh\nexit 0\n")
	caddyBinary := filepath.Join(t.TempDir(), "caddy")
	if err := os.WriteFile(caddyBinary, []byte("caddy-fixture"), 0755); err != nil {
		t.Fatal(err)
	}
	credentials := filepath.Join(root, "var", "lib", "boetticher", "credentials")
	if err := os.MkdirAll(credentials, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"cloudflare-dns-token", "statuspage-password"} {
		if err := os.WriteFile(filepath.Join(credentials, name+".cred"), []byte("synthetic-credential"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	env := append([]string(nil), os.Environ()...)
	env = append(env, "PATH="+fakeBin+":"+os.Getenv("PATH"), "BOETTICHER_OBSERVABILITY_ASSETS="+assetRoot, "BOETTICHER_OBSERVABILITY_CADDY_BINARY="+caddyBinary, "BOETTICHER_OBSERVABILITY_PUBLIC_DOMAIN=davebarton.cc", "BOETTICHER_OBSERVABILITY_METRICS_CONTROLLER=10.10.10.21", "BOETTICHER_OBSERVABILITY_METRICS_HOST=10.10.10.22", "BOETTICHER_OBSERVABILITY_METRICS_RUNTIME=10.10.10.20", "BOETTICHER_OBSERVABILITY_INGEST_SOURCES=10.10.10.21 10.10.10.22 10.10.10.20")
	cmd := exec.Command("sh", installerPath(t), "caddy", "--root", root)
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("internal-only Caddy staging failed: %v\n%s", err, output)
	}
	config, err := os.ReadFile(filepath.Join(root, "etc", "boetticher", "caddy", "Caddyfile"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(config)
	for _, required := range []string{"admin unix//run/caddy/admin.sock", "auto_https disable_redirects", "bind 10.10.10.20", "https://observability.davebarton.cc", "https://status.davebarton.cc", "https://metrics.davebarton.cc", "https://ingest.davebarton.cc", "basic_auth", "BOETTICHER_METRICS_PASSWORD_HASH", "remote_ip 10.10.10.20", "remote_ip 10.10.10.21 10.10.10.22 10.10.10.20", "respond 403"} {
		if !strings.Contains(text, required) {
			t.Errorf("Caddy config missing %q: %s", required, text)
		}
	}
	if strings.Contains(text, "bind 0.0.0.0") || strings.Contains(text, "http://") {
		t.Fatalf("Caddy config exposes an unapproved public or unresolved route: %s", text)
	}
}

func TestCollectionInstallerPinsTargetsAndKeepsTLSOutOfArguments(t *testing.T) {
	scriptPath := filepath.Join(filepath.Dir(installerPath(t)), "install-observability-collection.sh")
	script, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	for _, required := range []string{"node-exporter-$arch", "--continue-at -", "--proto '=https'", "basic_auth_users:", "--read-token-hash", "--key=-", "--cert=-", "systemd-journal-upload.service", "boetticher-node-exporter.service"} {
		if !strings.Contains(text, required) {
			t.Errorf("collection installer is missing %q", required)
		}
	}
	if strings.Contains(text, "--key ") || strings.Contains(text, "--password ") {
		t.Fatal("collection installer passes private material as an argument")
	}
	for _, required := range []string{"TrustedCertificateFile=/etc/ssl/certs/ca-certificates.crt", "chown \"root:$service_user\" \"$web_config.new\"", "--web.config.file=$guest_web_config", "ExecStart=", "ExecStart=/usr/lib/systemd/systemd-journal-upload --key=- --cert=- --save-state=/var/lib/systemd/journal-upload/state", "Restart=on-failure", "RestartSec=10s", "systemctl restart systemd-journal-upload.service"} {
		if !strings.Contains(text, required) {
			t.Fatalf("collection TLS permission contract missing %q", required)
		}
	}
}

func TestCollectionInstallerExecutesAgainstStagedRoot(t *testing.T) {
	root := t.TempDir()
	fakeBin := t.TempDir()
	assetRoot := filepath.Join(t.TempDir(), "assets")
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "passwd"), []byte("root:x:0:0:root:/root:/bin/sh\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(assetRoot, 0755); err != nil {
		t.Fatal(err)
	}
	archiveRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(archiveRoot, "node_exporter"), []byte("node-exporter-fixture"), 0755); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "node-exporter.tar.gz")
	cmd := exec.Command("tar", "-czf", archive, "-C", archiveRoot, "node_exporter")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create node-exporter archive: %v\n%s", err, output)
	}
	digest := sha256.Sum256(mustReadFile(t, archive))
	if err := os.WriteFile(filepath.Join(assetRoot, "catalog.json"), []byte(fmt.Sprintf(`{"node-exporter-amd64":{"url":"https://fixture.invalid/node-exporter.tar.gz","sha256":"%x"}}`, digest)), 0644); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, filepath.Join(fakeBin, "useradd"), "#!/bin/sh\nset -eu\nroot=/\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = --root ]; then root=$2; shift 2; continue; fi\n  account=$1; shift\ndone\nprintf '%s:x:2200:2200::/var/lib/%s:/usr/sbin/nologin\\n' \"$account\" \"$account\" >> \"$root/etc/passwd\"\n")
	writeExecutable(t, filepath.Join(fakeBin, "chown"), "#!/bin/sh\nexit 0\n")
	writeExecutable(t, filepath.Join(fakeBin, "systemctl"), "#!/bin/sh\nexit 0\n")
	writeExecutable(t, filepath.Join(fakeBin, "curl"), "#!/bin/sh\nset -eu\noutput=\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = --output ]; then output=$2; shift 2; continue; fi\n  shift\ndone\ncp \"$TEST_NODE_EXPORTER_ARCHIVE\" \"$output\"\n")
	env := append([]string(nil), os.Environ()...)
	env = append(env, "PATH="+fakeBin+":"+os.Getenv("PATH"), "TEST_NODE_EXPORTER_ARCHIVE="+archive, "BOETTICHER_OBSERVABILITY_ASSETS="+assetRoot)
	collectionInstaller := filepath.Join(filepath.Dir(installerPath(t)), "install-observability-collection.sh")
	cmd = exec.Command("sh", collectionInstaller, "--root", root, "--arch", "amd64", "--name", "proxmox-host", "--address", "10.10.99.5", "--kind", "host", "--collector-url", "https://ingest.davebarton.cc:443", "--read-token-hash", "$2a$10$fixture")
	cmd.Env = env
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("staged collection installer failed: %v\n%s", err, output)
	}
	webInfo, err := os.Stat(filepath.Join(root, "etc", "boetticher", "observability", "node-exporter-web.yml"))
	if err != nil || webInfo.Mode().Perm() != 0640 {
		t.Fatalf("exporter authentication configuration must remain private: %v", err)
	}
	unit := string(mustReadFile(t, filepath.Join(root, "etc", "systemd", "system", "systemd-journal-upload.service.d", "boetticher.conf")))
	if !strings.Contains(unit, "--save-state=/var/lib/systemd/journal-upload/state") || strings.Contains(unit, "$tls_dir") {
		t.Fatalf("staged uploader unit has incorrect native state configuration: %s", unit)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestProviderInstallerTerminatesCredentialHashInput(t *testing.T) {
	script := mustReadFile(t, "../../scripts/install-observability-providers.sh")
	text := string(script)
	for _, credential := range []string{"statuspage-password.cred", "node-exporter-read-token.cred"} {
		if !strings.Contains(text, "cat /var/lib/boetticher/credentials/"+credential+"; printf '\\n'") {
			t.Fatalf("credential %s is not terminated before Caddy hashing", credential)
		}
	}
}

func TestCollectionUploaderUsesSingleTrustConfiguration(t *testing.T) {
	script := mustReadFile(t, "../../scripts/install-observability-collection.sh")
	text := string(script)
	if !strings.Contains(text, "TrustedCertificateFile=/etc/ssl/certs/ca-certificates.crt") || strings.Contains(text, "ExecStart=/usr/lib/systemd/systemd-journal-upload --key=- --cert=- --trust=") {
		t.Fatal("journal upload configured duplicate trust options")
	}
}
