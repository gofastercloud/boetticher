package proxmox

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gofastercloud/boetticher/internal/model"
)

type CloudInitFiles struct {
	MetaData      string
	UserData      string
	NetworkConfig string
}

// RenderFirewallCloudInit creates only first-boot transport state. Runtime
// firewall policy, DHCP scopes, and forwarding remain deployment-derived.
func RenderFirewallCloudInit(guest GuestPlan) (CloudInitFiles, error) {
	return renderFirewallCloudInit(guest, "")
}

// RenderFirewallCloudInitWithKey adds the durable operator bootstrap key to
// the NoCloud user configuration. The key is transport state only; it is not
// part of the firewall artifact or the canonical site model. Temporary Apply
// authority is installed separately after the immutable plan is accepted.
func RenderFirewallCloudInitWithKey(guest GuestPlan, operatorPublicKey string) (CloudInitFiles, error) {
	if err := ValidatePublicKey(operatorPublicKey); err != nil {
		return CloudInitFiles{}, err
	}
	return renderFirewallCloudInit(guest, operatorPublicKey)
}

func renderFirewallCloudInit(guest GuestPlan, operatorPublicKey string) (CloudInitFiles, error) {
	if guest.Name != "lab-fw-01" || guest.Address != "10.10.99.1" {
		return CloudInitFiles{}, fmt.Errorf("unexpected firewall bootstrap identity %s/%s", guest.Name, guest.Address)
	}
	var network strings.Builder
	network.WriteString("version: 2\nethernets:\n")
	for _, nic := range guest.NICs {
		if nic.Name == "" || nic.MAC == "" {
			return CloudInitFiles{}, fmt.Errorf("firewall bootstrap NIC %q lacks stable MAC identity", nic.Name)
		}
		fmt.Fprintf(&network, "  %s:\n    match:\n      macaddress: %s\n    set-name: %s\n", nic.Name, nic.MAC, nic.Name)
		if nic.Method == "dhcp" {
			network.WriteString("    dhcp4: true\n")
		} else if nic.Address != "" {
			fmt.Fprintf(&network, "    addresses: [%s/24]\n", nic.Address)
		}
	}
	userData := "#cloud-config\nhostname: lab-fw-01\nmanage_etc_hosts: true\nusers:\n  - name: labadmin\n    shell: /bin/bash\n"
	if operatorPublicKey != "" {
		// JSON strings are valid YAML scalars and preserve an OpenSSH comment
		// without allowing it to alter the cloud-init document structure.
		userData += "    ssh_authorized_keys:\n      - " + strconv.Quote(operatorPublicKey) + "\n"
		// Root access is a deployment-only transport. The deploy command removes
		// this key and disables root SSH after all guests converge successfully.
		userData += "  - name: root\n    ssh_authorized_keys:\n      - " + strconv.Quote(operatorPublicKey) + "\n"
	}
	userData += "ssh_pwauth: false\ndisable_root: " + strconv.FormatBool(operatorPublicKey == "") + "\n"
	fsSetup := strings.Builder{}
	mounts := strings.Builder{}
	for _, name := range []string{"ssh-identity", "kea-leases", "firewall-telemetry"} {
		volume, index, ok := guestVolume(guest, name)
		if !ok {
			continue
		}
		if _, err := persistentVolumeSerial(volume); err != nil {
			return CloudInitFiles{}, fmt.Errorf("firewall %s volume: %w", name, err)
		}
		// Debian exposes PVE's virtio-scsi disks by their stable assigned
		// controller slot. The QEMU serial is retained for Proxmox-side
		// ownership checks, but does not produce a usable guest by-id link.
		device := fmt.Sprintf("/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi%d", index+1)
		label := "boetticher-" + name
		fmt.Fprintf(&fsSetup, "  - label: %s\n    filesystem: ext4\n    device: %s\n    overwrite: false\n", label, device)
		fmt.Fprintf(&mounts, "  - [\"%s\", \"%s\", \"ext4\", \"defaults,nofail\", \"0\", \"2\"]\n", device, volume.MountPath)
	}
	if fsSetup.Len() > 0 {
		userData += "fs_setup:\n" + fsSetup.String() + "mounts:\n" + mounts.String()
	}
	userData += "write_files:\n  - path: /etc/sysctl.d/boetticher-forwarding.conf\n    permissions: '0644'\n    content: |\n      net.ipv4.ip_forward=0\n      net.ipv6.conf.all.forwarding=0\n"
	return CloudInitFiles{
		MetaData:      "instance-id: boetticher-firewall-1.0.0\nlocal-hostname: lab-fw-01\n",
		UserData:      userData,
		NetworkConfig: network.String(),
	}, nil
}

func guestVolume(guest GuestPlan, name string) (model.PersistentVolumeDeclaration, int, bool) {
	for index, volume := range guest.Volumes {
		if volume.Name == name {
			return volume, index, true
		}
	}
	return model.PersistentVolumeDeclaration{}, 0, false
}

func cloudInitSnippetNames(vmid int) map[string]string {
	prefix := fmt.Sprintf("boetticher-%d", vmid)
	return map[string]string{"meta": prefix + "-meta.yaml", "user": prefix + "-user.yaml", "network": prefix + "-network.yaml"}
}

func cloudInitCICustom(vmid int) string {
	names := cloudInitSnippetNames(vmid)
	return fmt.Sprintf("user=local:snippets/%s,network=local:snippets/%s,meta=local:snippets/%s", names["user"], names["network"], names["meta"])
}
