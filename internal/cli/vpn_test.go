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

func TestPrepareVPNModulesAcceptsNamedSelectorAndRejectsUnsafeInput(t *testing.T) {
	enabled := true
	modules := clientservices.Modules{VPN: &clientservices.VPNConfig{Enabled: &enabled, Location: "australia"}}
	prepared, _, err := prepareVPNModules(modules, model.NewSite("lab", "controller-local", model.GatewayModeManaged))
	if err != nil || prepared.VPN.Location != "australia" {
		t.Fatalf("named VPN selection was not retained: %#v err=%v", prepared, err)
	}
	modules.VPN.Location = "australia/status"
	if _, _, err := prepareVPNModules(modules, model.NewSite("lab", "controller-local", model.GatewayModeManaged)); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("unsafe VPN selector was accepted: %v", err)
	}
}

func TestVPNApplyParsesLocation(t *testing.T) {
	opts, err := parseVPNOptions("apply", []string{"--location", "Sydney", "--yes"})
	if err != nil || opts.location != "Sydney" {
		t.Fatalf("location option = %#v err=%v", opts, err)
	}
}

func TestRetainedVPNSelectorLegacyAndBoundRoundTrip(t *testing.T) {
	t.Setenv(vpnStateRootEnv, t.TempDir())
	s := model.NewSite("lab", "controller-local", model.GatewayModeManaged)
	if err := pathguard.MkdirAll(vpnStateDir(s), 0700); err != nil {
		t.Fatal(err)
	}
	legacy := "[Interface]\nPrivateKey = " + strings.Repeat("A", 43) + "\n"
	if err := pathguard.WriteFileWithParentMode(vpnStatePath(s, vpnProfileFile), []byte(legacy), 0600, 0700); err != nil {
		t.Fatal(err)
	}
	selector, err := retainedVPNSelector(s)
	if err != nil || selector != "europe" {
		t.Fatalf("legacy selector = %q err=%v", selector, err)
	}
	if err := pathguard.WriteFileWithParentMode(vpnStatePath(s, vpnProfileFile), []byte("[Interface]\n# Boetticher-Selector: Sydney\n"), 0600, 0700); err != nil {
		t.Fatal(err)
	}
	selector, err = retainedVPNSelector(s)
	if err != nil || selector != "Sydney" {
		t.Fatalf("bound selector = %q err=%v", selector, err)
	}
}
