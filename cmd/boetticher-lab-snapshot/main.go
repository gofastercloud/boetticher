package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"github.com/gofastercloud/boetticher/internal/controllerstatus"
	"github.com/gofastercloud/boetticher/internal/observability"
)

type observation struct {
	Name       string    `json:"name"`
	Kind       string    `json:"kind"`
	Desired    string    `json:"desired"`
	State      string    `json:"state"`
	Source     string    `json:"source"`
	ObservedAt time.Time `json:"observed_at"`
	Detail     string    `json:"detail,omitempty"`
	Error      string    `json:"error,omitempty"`
}

type facts struct {
	Observations []observation `json:"observations"`
}

func main() {
	output := "/var/lib/boetticher/labviewer/facts.json"
	if value := os.Getenv("BOETTICHER_LAB_FACTS_PATH"); value != "" {
		output = value
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	now := time.Now().UTC()
	result := facts{}
	config, err := controllerhost.LoadConfig()
	if err != nil {
		result.Observations = append(result.Observations, observation{Name: "controller.config", Kind: "controller", Desired: "configured", State: "unknown", Source: "controller.yml", ObservedAt: now, Error: err.Error()})
	} else {
		collectHost(ctx, config, now, &result)
		collectServices(ctx, config, now, &result)
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.MkdirAll(filepath.Dir(output), 0750); err != nil {
		panic(err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(output), ".facts-*")
	if err != nil {
		panic(err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0640); err != nil {
		panic(err)
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		panic(err)
	}
	if err := tmp.Close(); err != nil {
		panic(err)
	}
	if err := os.Rename(tmpName, output); err != nil {
		panic(err)
	}
}

func collectHost(ctx context.Context, config controllerhost.LabConfig, now time.Time, result *facts) {
	collector := controllerstatus.ProxmoxCollector{}
	snapshot, err := collector.Collect(ctx)
	if err != nil {
		result.Observations = append(result.Observations, observation{Name: "proxmox.host", Kind: "host", Desired: "enrolled", State: "unknown", Source: "proxmox.read-only", ObservedAt: now, Error: err.Error()})
		return
	}
	result.Observations = append(result.Observations, observation{Name: "proxmox.host", Kind: "host", Desired: "enrolled", State: "observed", Source: "proxmox.read-only", ObservedAt: snapshot.FetchedAt, Detail: fmt.Sprintf("node=%s version=%s cpu=%.1f%% memory_used=%d memory_total=%d", snapshot.Host.Node, snapshot.Host.Version, snapshot.Host.CPUPercent, snapshot.Host.MemoryUsed, snapshot.Host.MemoryTotal)})
	for _, guest := range snapshot.Guests {
		state := strings.ToLower(strings.TrimSpace(guest.Status))
		if state == "" {
			state = "unknown"
		}
		result.Observations = append(result.Observations, observation{Name: fmt.Sprintf("guest.%d", guest.VMID), Kind: "guest", Desired: "registered", State: state, Source: "proxmox.read-only", ObservedAt: snapshot.FetchedAt, Detail: fmt.Sprintf("name=%s kind=%s", guest.Name, guest.Kind)})
	}
	_ = config
}

func collectServices(ctx context.Context, config controllerhost.LabConfig, now time.Time, result *facts) {
	runner, err := observabilityTransport(config)
	if err != nil {
		result.Observations = append(result.Observations, observation{Name: "observability.services", Kind: "module", Desired: "enabled", State: "unknown", Source: "observability.read-only", ObservedAt: now, Error: err.Error()})
		return
	}
	binding, _ := observability.BindingFor("observability")
	client := observability.HostClient{Transport: runner}
	for _, service := range observability.ServicesForModules(config.Modules) {
		status, statusErr := client.ServiceStatus(ctx, binding, service)
		state := strings.TrimSpace(status)
		if state == "" {
			state = "unknown"
		}
		item := observation{Name: "service." + service, Kind: "service", Desired: "active", State: state, Source: "systemd.read-only", ObservedAt: now}
		if statusErr != nil {
			item.State = "unknown"
			item.Error = statusErr.Error()
		} else if health, healthErr := client.ProviderHealth(ctx, binding, service); healthErr == nil {
			item.Detail = health
		} else {
			item.Detail = healthErr.Error()
		}
		result.Observations = append(result.Observations, item)
	}
}

var observabilityTransport = func(config controllerhost.LabConfig) (observability.Runner, error) {
	return controllerhost.TransportFor(config)
}
