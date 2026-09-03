package proxmox

import (
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
	"gopkg.in/yaml.v3"
)

func TestFirewallCloudInitUsesStableInterfaceIdentities(t *testing.T) {
	guest := GuestPlan{Name: "lab-fw-01", Address: "10.10.99.1", NICs: []GuestNIC{
		{Name: "wan0", MAC: "02:00:00:00:01:01", Method: "dhcp"},
		{Name: "trusted0", MAC: "02:00:00:00:01:02", Method: "static", Address: "10.10.30.1"},
		{Name: "servers0", MAC: "02:00:00:00:01:03", Method: "static", Address: "10.10.20.1"},
		{Name: "sandbox0", MAC: "02:00:00:00:01:04", Method: "static", Address: "10.10.40.1"},
		{Name: "mgmt0", MAC: "02:00:00:00:01:05", Method: "static", Address: "10.10.99.1"},
		{Name: "transit0", MAC: "02:00:00:00:01:06", Method: "static", Address: "10.10.5.1"},
		{Name: "infra0", MAC: "02:00:00:00:01:07", Method: "static", Address: "10.10.10.1"},
	}}
	files, err := RenderFirewallCloudInit(guest)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"set-name: wan0", "set-name: trusted0", "set-name: servers0", "set-name: sandbox0", "set-name: mgmt0", "set-name: transit0", "set-name: infra0", "net.ipv4.ip_forward=0", "net.ipv6.conf.all.forwarding=0"} {
		if !strings.Contains(files.NetworkConfig+files.UserData, value) {
			t.Fatalf("cloud-init omitted %q", value)
		}
	}
	if strings.Contains(files.UserData, "ssh-ed25519") || strings.Contains(files.UserData, "password:") {
		t.Fatal("firewall cloud-init embedded operator or password material")
	}
	if strings.Contains(files.UserData, "sudo:") || strings.Contains(files.UserData, "groups: [sudo]") || !strings.Contains(files.UserData, "disable_root: true") {
		t.Fatalf("firewall cloud-init grants durable labadmin privilege: %s", files.UserData)
	}
}

func TestFirewallCloudInitInjectsOperatorKeyOnlyAtDeployment(t *testing.T) {
	guest := GuestPlan{Name: "lab-fw-01", Address: "10.10.99.1", NICs: []GuestNIC{{Name: "mgmt0", MAC: "02:00:00:00:01:05", Method: "static", Address: "10.10.99.1"}}}
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBoetticherTrial operator #1"
	files, err := RenderFirewallCloudInitWithKey(guest, key)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(files.UserData, "ssh_authorized_keys:") || !strings.Contains(files.UserData, key) {
		t.Fatalf("firewall bootstrap key was not injected into deployment-only NoCloud data: %s", files.UserData)
	}
	var document struct {
		Users       []any `yaml:"users"`
		DisableRoot bool  `yaml:"disable_root"`
	}
	if err := yaml.Unmarshal([]byte(files.UserData), &document); err != nil {
		t.Fatalf("firewall cloud-init is not valid YAML: %v", err)
	}
	found := false
	for _, rawUser := range document.Users {
		user, ok := rawUser.(map[string]any)
		if !ok || user["name"] != "labadmin" {
			continue
		}
		keys, ok := user["ssh_authorized_keys"].([]any)
		if !ok || len(keys) != 1 || keys[0] != key {
			t.Fatalf("firewall bootstrap key was not preserved as one YAML scalar: %#v", user["ssh_authorized_keys"])
		}
		found = true
		break
	}
	if !found {
		t.Fatal("firewall cloud-init does not configure labadmin")
	}
	if document.DisableRoot {
		t.Fatal("deployment cloud-init disables the temporary root transport")
	}
	rootFound := false
	for _, rawUser := range document.Users {
		user, ok := rawUser.(map[string]any)
		if !ok || user["name"] != "root" {
			continue
		}
		keys, ok := user["ssh_authorized_keys"].([]any)
		if !ok || len(keys) != 1 || keys[0] != key {
			t.Fatalf("temporary root key was not preserved as one YAML scalar: %#v", user["ssh_authorized_keys"])
		}
		rootFound = true
	}
	if !rootFound {
		t.Fatal("deployment cloud-init does not configure temporary root access")
	}
	if strings.Contains(files.MetaData+files.NetworkConfig, key) {
		t.Fatal("operator key leaked into unrelated NoCloud documents")
	}
}

func TestFirewallCloudInitRejectsInvalidOperatorKey(t *testing.T) {
	guest := GuestPlan{Name: "lab-fw-01", Address: "10.10.99.1", NICs: []GuestNIC{{Name: "mgmt0", MAC: "02:00:00:00:01:05", Method: "static", Address: "10.10.99.1"}}}
	if _, err := RenderFirewallCloudInitWithKey(guest, "not-a-key"); err == nil {
		t.Fatal("invalid operator key was accepted")
	}
}

func TestFirewallCloudInitDoesNotDuplicateStaticPrefixLength(t *testing.T) {
	guest := GuestPlan{Name: "lab-fw-01", Address: "10.10.99.1", NICs: []GuestNIC{
		{Name: "trusted0", MAC: "02:00:00:00:01:02", Method: "static", Address: "10.10.30.1"},
	}}
	files, err := RenderFirewallCloudInit(guest)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(files.NetworkConfig, "addresses: [10.10.30.1/24]") || strings.Contains(files.NetworkConfig, "/24/24") {
		t.Fatalf("invalid static address rendered: %s", files.NetworkConfig)
	}
}

func TestFirewallCloudInitRejectsUnstableNICIdentity(t *testing.T) {
	if _, err := RenderFirewallCloudInit(GuestPlan{Name: "lab-fw-01", Address: "10.10.99.1", NICs: []GuestNIC{{Name: "wan0", Method: "dhcp"}}}); err == nil {
		t.Fatal("cloud-init accepted a NIC without a stable MAC")
	}
}

func TestFirewallCloudInitMountsDeclaredVolumesByStableDiskIdentity(t *testing.T) {
	guest := GuestPlan{
		Name: "lab-fw-01", Address: "10.10.99.1",
		NICs: []GuestNIC{{Name: "mgmt0", MAC: "02:00:00:00:01:05", Method: "static", Address: "10.10.99.1"}},
		Volumes: []model.PersistentVolumeDeclaration{
			{Name: "ssh-identity", Module: "firewall", Guest: "lab-fw-01", MountPath: "/var/lib/boetticher/identity/ssh"},
			{Name: "kea-leases", Module: "firewall", Guest: "lab-fw-01", MountPath: "/var/lib/kea"},
			{Name: "firewall-telemetry", Module: "firewall", Guest: "lab-fw-01", MountPath: "/var/lib/boetticher/firewall-telemetry"},
		},
	}
	files, err := RenderFirewallCloudInit(guest)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(files.UserData, "fs_setup:") != 1 || strings.Count(files.UserData, "mounts:") != 1 {
		t.Fatalf("firewall cloud-init emitted duplicate storage sections: %s", files.UserData)
	}
	var document struct {
		FSSetup []struct {
			Label    string `yaml:"label"`
			Device   string `yaml:"device"`
			Override bool   `yaml:"overwrite"`
		} `yaml:"fs_setup"`
		Mounts [][]string `yaml:"mounts"`
	}
	if err := yaml.Unmarshal([]byte(files.UserData), &document); err != nil {
		t.Fatalf("firewall cloud-init is not valid YAML: %v", err)
	}
	if len(document.FSSetup) != 3 || len(document.Mounts) != 3 {
		t.Fatalf("unexpected persistent volume bootstrap: %#v", document)
	}
	if document.FSSetup[0].Label != "boetticher-ssh-identity" || document.FSSetup[1].Label != "boetticher-kea-leases" || document.FSSetup[2].Label != "boetticher-firewall-telemetry" {
		t.Fatalf("unexpected persistent volume labels: %#v", document.FSSetup)
	}
	if document.FSSetup[0].Device != "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi1" {
		t.Fatalf("SSH identity device is not stable: %#v", document.FSSetup[0])
	}
	if document.Mounts[1][1] != "/var/lib/kea" || document.Mounts[1][3] != "defaults,nofail" {
		t.Fatalf("Kea volume mount is not explicit: %#v", document.Mounts[1])
	}
	if document.Mounts[2][1] != "/var/lib/boetticher/firewall-telemetry" || document.Mounts[2][3] != "defaults,nofail" {
		t.Fatalf("telemetry volume mount is not explicit: %#v", document.Mounts[2])
	}
}
