package controller

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEvaluateSnapshotReportsEveryControllerCheck(t *testing.T) {
	checks := EvaluateSnapshot(StatusSnapshot{Platform: true, Runtime: true, Go: true, Ansible: true, SSH: true, Updates: true, Timers: true, Time: true, Journal: true, Logrotate: true, Log2RAM: true, Log2RAMTimer: true, RebootComplete: true, GPIO: true})
	if len(checks) != 14 {
		t.Fatalf("check count = %d, want 14", len(checks))
	}
	for _, check := range checks {
		if !check.Passed {
			t.Fatalf("all-ready snapshot reported %s failed", check.Name)
		}
	}
	for _, check := range checks {
		if check.Name == "Go" && check.Detail != "1.26.6" {
			t.Fatalf("Go status detail = %q, want 1.26.6", check.Detail)
		}
	}
	checks = EvaluateSnapshot(StatusSnapshot{Platform: true})
	for _, check := range checks {
		if check.Name != "Platform" && check.Passed {
			t.Fatalf("incomplete snapshot reported %s passed", check.Name)
		}
	}
}

func TestMissingOptionalBlinktDoesNotBlockReadiness(t *testing.T) {
	checks := EvaluateSnapshot(StatusSnapshot{Platform: true})
	for _, check := range checks {
		if check.Name == "GPIO" {
			if check.Passed || !check.Optional || check.BlocksReadiness() {
				t.Fatalf("missing Blinkt check = %#v", check)
			}
			return
		}
	}
	t.Fatal("GPIO check was omitted")
}

func TestResolveRuntimeRequiresVersionedReleasePath(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "releases", "one"), 0755); err != nil {
		t.Fatal(err)
	}
	current := filepath.Join(root, "current")
	if err := os.Symlink(filepath.Join(root, "releases", "one"), current); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveRuntimeUnder(current, root); err != nil || got == "" {
		t.Fatalf("resolveRuntimeUnder() = %q, %v", got, err)
	}
	if _, err := resolveRuntimeUnder(t.TempDir(), root); err == nil {
		t.Fatal("runtime outside versioned release root was accepted")
	}
}

func TestLoadConfigRejectsMissingOperator(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.yml")
	if err := os.WriteFile(path, []byte("blinkt:\n  enabled: true\n  gpiochip: 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("controller config without an operator was accepted")
	}
}

func TestLoadConfigTreatsMissingGPIOChipAsUndiscovered(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.yml")
	if err := os.WriteFile(path, []byte("operator_user: pi\nblinkt:\n  enabled: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.Blinkt.GPIOChip != -1 {
		t.Fatalf("missing GPIO chip = %d, want undiscovered sentinel -1", config.Blinkt.GPIOChip)
	}
}
