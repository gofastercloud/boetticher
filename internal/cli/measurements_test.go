package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/gofastercloud/boetticher/internal/telemetry"
)

func TestOperationMeasurementsAggregateLowCardinalityKeys(t *testing.T) {
	var measurements operationMeasurements
	measurements.Observe(telemetry.Event{
		Category: "proxmox_api", Operation: "/nodes/pve/qemu/190/config", Method: "GET",
		Status: 200, Duration: 120 * time.Millisecond, Success: true,
	})
	measurements.Observe(telemetry.Event{
		Category: "proxmox_api", Operation: "/nodes/pve/tasks/UPID:pve:secret-looking-id:status", Method: "GET",
		Status: 200, Duration: 80 * time.Millisecond, Success: true,
	})
	measurements.Observe(telemetry.Event{
		Category: "ssh", Operation: "command", Target: "root@192.0.2.10",
		Status: 1, Duration: 10 * time.Millisecond,
	})
	measurements.Observe(telemetry.Event{
		Category: "provider_api", Operation: "generate_profile", Target: "airvpn-generator",
		Method: "GET", Status: 200, Duration: 40 * time.Millisecond, Success: true,
	})
	measurements.Observe(telemetry.Event{
		Category: "ansible", Operation: "playbook", Target: "all",
		Status: 0, Duration: 2 * time.Second, Success: true, Changed: true,
	})
	measurements.Observe(telemetry.Event{
		Category: "artifact_transfer", Operation: "controller_to_proxmox", Target: "import",
		Bytes: 4096, Duration: 50 * time.Millisecond, Success: true, Changed: true,
	})

	if measurements.ProxmoxAPI.Count != 2 || measurements.ProxmoxAPI.DurationMS != 200 {
		t.Fatalf("unexpected Proxmox measurements: %+v", measurements.ProxmoxAPI)
	}
	if measurements.SSH.Count != 1 || measurements.SSH.Failures != 1 {
		t.Fatalf("unexpected SSH measurements: %+v", measurements.SSH)
	}
	if measurements.Ansible.Count != 1 || measurements.Ansible.Changed != 1 {
		t.Fatalf("unexpected Ansible measurements: %+v", measurements.Ansible)
	}
	if measurements.Artifact.Count != 1 || measurements.Artifact.Bytes != 4096 || measurements.Artifact.DurationMS != 50 || measurements.Artifact.Changed != 1 {
		t.Fatalf("unexpected artifact transfer measurements: %+v", measurements.Artifact)
	}
	if measurements.ProviderAPI.Count != 1 || measurements.ProviderAPI.DurationMS != 40 {
		t.Fatalf("unexpected provider measurements: %+v", measurements.ProviderAPI)
	}
	for key := range measurements.ProxmoxAPI.ByKey {
		if strings.Contains(key, "secret-looking-id") || strings.Contains(key, "/190/") {
			t.Fatalf("measurement key retained high-cardinality identity: %q", key)
		}
	}
	if got := measurements.summaryLine(); !strings.Contains(got, "Proxmox API 2") || !strings.Contains(got, "Provider API 1") || !strings.Contains(got, "SSH 1") || !strings.Contains(got, "Ansible 1") || !strings.Contains(got, "artifact transfer 1") {
		t.Fatalf("unexpected measurement summary: %s", got)
	}
}
