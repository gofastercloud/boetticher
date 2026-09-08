package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"github.com/gofastercloud/boetticher/internal/observability"
)

type capabilityStatusRunner struct{ bifrostDown bool }

func (r capabilityStatusRunner) Run(_ context.Context, command string) (controllerhost.Result, error) {
	b, _ := observability.BindingFor("observability")
	if strings.HasPrefix(command, "pct config ") {
		return controllerhost.Result{Stdout: []byte("hostname: " + b.Hostname + "\ntags: boetticher;managed;module-observability;boetticher-module-observability\nnet0: name=eth0,bridge=vmbr1,tag=10,ip=10.10.10.20/24\n")}, nil
	}
	if strings.Contains(command, "systemctl is-active") {
		if r.bifrostDown && strings.Contains(command, "bifrost.service") {
			return controllerhost.Result{Stdout: []byte("inactive\n")}, nil
		}
		return controllerhost.Result{Stdout: []byte("active\n")}, nil
	}
	if strings.Contains(command, "pct status") {
		return controllerhost.Result{Stdout: []byte("status: running\n")}, nil
	}
	return controllerhost.Result{Stdout: []byte("installed")}, nil
}

func TestCapabilityStatusUsesOnlyOwnedComponentServices(t *testing.T) {
	previousLoad := loadLabConfig
	previousTransport := observabilityTransport
	defer func() { loadLabConfig = previousLoad; observabilityTransport = previousTransport }()
	enabled := true
	loadLabConfig = func() (controllerhost.LabConfig, error) {
		return controllerhost.LabConfig{Name: "lab", Proxmox: controllerhost.ProxmoxConfig{Address: "192.0.2.10", User: "root", Repository: "no-subscription"}, Modules: clientservices.Modules{Observability: &clientservices.ObservabilityConfig{Enabled: &enabled}}}, nil
	}
	observabilityTransport = func(controllerhost.LabConfig) (observability.Runner, error) {
		return capabilityStatusRunner{bifrostDown: true}, nil
	}
	var out, errOut bytes.Buffer
	if err := runObservabilityCapability("logging", "status", nil, nil, &out, &errOut); err != nil {
		t.Fatalf("logging status failed while unrelated Bifrost was down: %v", err)
	}
	if strings.Contains(out.String(), "bifrost") {
		t.Fatalf("logging status included unrelated Bifrost state: %s", out.String())
	}
	out.Reset()
	if err := runObservabilityCapability("observability", "status", nil, nil, &out, &errOut); err == nil || !strings.Contains(err.Error(), "bifrost.service unhealthy") {
		t.Fatalf("whole observability status did not report Bifrost failure: err=%v output=%s", err, out.String())
	}
}
