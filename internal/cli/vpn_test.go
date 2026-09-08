package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/pathguard"
)

func TestVPNCommandDispatchStaysOnPublicCapability(t *testing.T) {
	err := runModuleWithInput([]string{"vpn", "unsupported"}, strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	if err == nil || !strings.Contains(err.Error(), `module capability "vpn" does not implement action`) {
		t.Fatalf("VPN dispatch error = %v", err)
	}
}

func TestVPNPublicLifecycleArgumentBoundaryIsDirectlyDispatched(t *testing.T) {
	cases := []struct {
		action string
		args   []string
		want   string
	}{
		{"plan", []string{"--yes"}, "--yes is only valid"},
		{"apply", []string{"--api-key-stdin"}, "requires --yes"},
		{"status", []string{"--yes"}, "--yes is only valid"},
		{"teardown", []string{"--plan", "--yes"}, "cannot be combined"},
	}
	for _, tc := range cases {
		err := runVPNCapability(tc.action, tc.args, strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("vpn %s boundary error=%v, want %q", tc.action, err, tc.want)
		}
	}
}

func TestVPNMaterialRetainsReturnedDeviceIDWhenProfileIsMissing(t *testing.T) {
	t.Setenv(vpnStateRootEnv, t.TempDir())
	siteModel := model.NewSite("lab", "controller-local", model.GatewayModeManaged)
	if err := pathguard.MkdirAll(vpnStateDir(siteModel), 0700); err != nil {
		t.Fatal(err)
	}
	if err := pathguard.WriteFileWithParentMode(filepath.Join(vpnStateDir(siteModel), vpnDeviceFile), []byte("device-123\n"), 0600, 0700); err != nil {
		t.Fatal(err)
	}
	_, deviceID, present, err := loadVPNMaterial(siteModel)
	if err != nil || present || deviceID != "device-123" {
		t.Fatalf("retained device state = profile-present:%v id:%q err:%v", present, deviceID, err)
	}
}

func TestVPNAPIKeyProvisioningRequiresExplicitApproval(t *testing.T) {
	if _, err := parseVPNOptions("apply", []string{"--api-key-stdin"}); err != nil {
		t.Fatal(err)
	}
	if err := runVPNCapability("apply", []string{"--api-key-stdin"}, strings.NewReader("key"), &strings.Builder{}, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "requires --yes") {
		t.Fatalf("unapproved API-key provisioning error = %v", err)
	}
}

func TestPrepareVPNModulesRequiresEuropeSelection(t *testing.T) {
	enabled := true
	modules := clientservices.Modules{VPN: &clientservices.VPNConfig{Enabled: &enabled, Location: "australia"}}
	if _, _, err := prepareVPNModules(modules, model.NewSite("lab", "controller-local", model.GatewayModeManaged)); err == nil || !strings.Contains(err.Error(), "Europe") {
		t.Fatalf("non-Europe VPN selection was accepted: %v", err)
	}
}
