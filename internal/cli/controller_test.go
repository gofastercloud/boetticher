package cli

import (
	"strings"
	"testing"
)

func TestControllerStatusDispatchDoesNotRequireAnInitializedSite(t *testing.T) {
	var output strings.Builder
	err := runController([]string{"status", "--operator", "pi"}, &output, &output)
	if err == nil {
		t.Fatal("controller status unexpectedly passed on the maintainer host")
	}
	if strings.Contains(output.String(), "Proxmox") || strings.Contains(output.String(), "site.yml") {
		t.Fatalf("controller status attempted lab state: %s", output.String())
	}
}

func TestControllerCommandHelpIsPublished(t *testing.T) {
	var output strings.Builder
	if err := run([]string{"controller", "--help"}, nil, &output, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "controller bootstrap") || !strings.Contains(output.String(), "controller status") {
		t.Fatalf("controller help omitted the local commands: %s", output.String())
	}
}

func TestControllerRejectsUnknownSubcommand(t *testing.T) {
	var output strings.Builder
	if err := runController([]string{"unknown"}, &output, &output); err == nil {
		t.Fatal("unknown controller command was accepted")
	}
}
