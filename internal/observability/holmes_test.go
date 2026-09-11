package observability

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
)

type holmesAskRunner struct {
	command string
	input   string
}

func (r *holmesAskRunner) Run(_ context.Context, command string) (controllerhost.Result, error) {
	if strings.Contains(command, "systemctl is-active") {
		return controllerhost.Result{Stdout: []byte("active\n")}, nil
	}
	if strings.HasPrefix(command, "pct config ") {
		b, _ := BindingFor("observability")
		return controllerhost.Result{Stdout: []byte(ownedGuestOutput(b, "boetticher;managed;module-observability;boetticher-module-observability", "name=eth0,bridge=vmbr1,tag=10,ip=10.10.10.20/24"))}, nil
	}
	return controllerhost.Result{}, nil
}

func (r *holmesAskRunner) RunWithStdin(_ context.Context, command string, stdin io.Reader) (controllerhost.Result, error) {
	r.command = command
	b, _ := io.ReadAll(stdin)
	r.input = string(b)
	return controllerhost.Result{Stdout: []byte("bounded Holmes answer")}, nil
}

func TestAskHolmesUsesOnDemandLocalSandboxAndStreamsQuestion(t *testing.T) {
	b, _ := BindingFor("observability")
	runner := &holmesAskRunner{}
	answer, err := (HostClient{Transport: runner}).AskHolmes(context.Background(), b, "operations", strings.NewReader("why is DNS slow?"))
	if err != nil {
		t.Fatal(err)
	}
	if answer != "bounded Holmes answer" || runner.input != "why is DNS slow?" {
		t.Fatalf("answer=%q input=%q", answer, runner.input)
	}
	for _, required := range []string{"mktemp -d /run/boetticher-holmes-ask", "install -o holmes -g holmes -m 0400", "timeout --signal=TERM --kill-after=5s", "setpriv --reuid=holmes --regid=holmes --init-groups --no-new-privs", "CREDENTIALS_DIRECTORY=", "/opt/boetticher/observability/holmes/holmes-runner.py", "--model-alias", "operations"} {
		if !strings.Contains(runner.command, required) {
			t.Errorf("ask command missing %q: %s", required, runner.command)
		}
	}
	if strings.Contains(runner.command, "why is DNS slow") || strings.Contains(runner.command, "Bearer ") {
		t.Fatalf("question or credential leaked into command: %s", runner.command)
	}
}

func TestHolmesRunnerAssetsPinAllowlistAndRoutes(t *testing.T) {
	root := filepath.Join("..", "..", "controller", "observability", "holmes")
	runner, err := os.ReadFile(filepath.Join(root, "holmes-runner.py"))
	if err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(filepath.Join(root, "holmes.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"PrometheusToolset()", "VictoriaLogsToolset()", "prometheus.subtype = \"victoriametrics\"", "prometheus.config = {\"prometheus_url\": \"http://127.0.0.1:8428\"}", "victorialogs.config = {\"api_url\": \"http://127.0.0.1:9428\"}", "check_prerequisites(silent=True)", "enabled_names != ALLOWLIST", "model=\"openai/\" + alias", "api_base=loopback", "args={\"max_tokens\": 1200}", "ToolCallingLLM(executor, 6, llm, tool_results_dir=None)", ".call(messages).result"} {
		if !strings.Contains(string(runner), required) {
			t.Errorf("Holmes runner missing %q", required)
		}
	}
	for _, required := range []string{"prometheus/metrics", "subtype: victoriametrics", "http://127.0.0.1:8428", "victorialogs", "http://127.0.0.1:9428"} {
		if !strings.Contains(string(config), required) {
			t.Errorf("Holmes config missing %q", required)
		}
	}
}
