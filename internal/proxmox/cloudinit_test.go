package proxmox

import (
	"strings"
	"testing"
)

func TestFirewallCloudInitUsesStableInterfaceIdentities(t *testing.T) {
	guest := GuestPlan{Name: "lab-fw-01", Address: "10.10.99.1", NICs: []GuestNIC{
		{Name: "wan0", MAC: "02:00:00:00:01:01", Method: "dhcp"},
		{Name: "trusted0", MAC: "02:00:00:00:01:02", Method: "static", Address: "10.10.10.1"},
		{Name: "servers0", MAC: "02:00:00:00:01:03", Method: "static", Address: "10.10.20.1"},
		{Name: "sandbox0", MAC: "02:00:00:00:01:04", Method: "static", Address: "10.10.50.1"},
		{Name: "mgmt0", MAC: "02:00:00:00:01:05", Method: "static", Address: "10.10.99.1"},
	}}
	files, err := RenderFirewallCloudInit(guest)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"set-name: wan0", "set-name: trusted0", "set-name: servers0", "set-name: sandbox0", "set-name: mgmt0", "net.ipv4.ip_forward=0", "net.ipv6.conf.all.forwarding=0"} {
		if !strings.Contains(files.NetworkConfig+files.UserData, value) {
			t.Fatalf("cloud-init omitted %q", value)
		}
	}
	if strings.Contains(files.UserData, "ssh-ed25519") || strings.Contains(files.UserData, "password:") {
		t.Fatal("firewall cloud-init embedded operator or password material")
	}
}

func TestFirewallCloudInitRejectsUnstableNICIdentity(t *testing.T) {
	if _, err := RenderFirewallCloudInit(GuestPlan{Name: "lab-fw-01", Address: "10.10.99.1", NICs: []GuestNIC{{Name: "wan0", Method: "dhcp"}}}); err == nil {
		t.Fatal("cloud-init accepted a NIC without a stable MAC")
	}
}

func TestRenderBuilderCloudInitUsesPublicBuildInputsOnly(t *testing.T) {
	files := RenderBuilderCloudInit()
	for name, content := range map[string]string{"meta": files.MetaData, "user": files.UserData, "network": files.NetworkConfig} {
		if content == "" {
			t.Fatalf("builder %s cloud-init is empty", name)
		}
		if strings.Contains(content, "age1") || strings.Contains(content, "BEGIN PRIVATE KEY") || strings.Contains(content, "SOPS") {
			t.Fatalf("builder %s cloud-init contains secret authority material", name)
		}
	}
	if !strings.Contains(files.UserData, "boetticher-build") || !strings.Contains(files.UserData, "scripts/scan-images.sh scan-images") {
		t.Fatal("builder cloud-init does not invoke the first-party build and qualification path")
	}
	if !strings.Contains(files.UserData, "qemu-guest-agent") || !strings.Contains(files.NetworkConfig, "dhcp4: true") {
		t.Fatal("builder cloud-init lacks guest-agent or bootstrap network setup")
	}
	if !strings.Contains(files.UserData, "trivy_0.69.3_Linux-64bit.tar.gz") || !strings.Contains(files.UserData, "1816b632dfe529869c740c0913e36bd1629cb7688bd5634f4a858c1d57c88b75") {
		t.Fatal("builder cloud-init does not pin the Trivy qualification input")
	}
}
