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

// RenderFirewallCloudInitWithKey adds the deployment-time operator key to the
// NoCloud user configuration. The key is transport state only; it is not part
// of the firewall artifact or the canonical site model.
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
	userData := "#cloud-config\nhostname: lab-fw-01\nmanage_etc_hosts: true\nusers:\n  - name: labadmin\n    shell: /bin/bash\n    groups: [sudo]\n    sudo: [\"ALL=(ALL) NOPASSWD:/usr/bin/systemctl, /usr/sbin/nft, /usr/sbin/kea-dhcp4, /usr/sbin/kea-dhcp-ddns, /bin/sh -c * /usr/bin/python3 /tmp/boetticher-ansible/ansible-tmp-*/*\"]\n"
	if operatorPublicKey != "" {
		// JSON strings are valid YAML scalars and preserve an OpenSSH comment
		// without allowing it to alter the cloud-init document structure.
		userData += "    ssh_authorized_keys:\n      - " + strconv.Quote(operatorPublicKey) + "\n"
	}
	userData += "ssh_pwauth: false\ndisable_root: true\n"
	fsSetup := strings.Builder{}
	mounts := strings.Builder{}
	for _, name := range []string{"ssh-identity", "kea-leases"} {
		volume, ok := guestVolume(guest, name)
		if !ok {
			continue
		}
		serial, err := persistentVolumeSerial(volume)
		if err != nil {
			return CloudInitFiles{}, fmt.Errorf("firewall %s volume: %w", name, err)
		}
		device := "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_" + serial
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

func guestVolume(guest GuestPlan, name string) (model.PersistentVolumeDeclaration, bool) {
	for _, volume := range guest.Volumes {
		if volume.Name == name {
			return volume, true
		}
	}
	return model.PersistentVolumeDeclaration{}, false
}

// RenderBuilderCloudInit prepares the temporary public-input build host
// without operator-specific state. It is useful for inspecting the public
// build contract; deployment uses RenderBuilderCloudInitWithKey so the
// builder's management identity is present in the custom user-data document.
func RenderBuilderCloudInit() CloudInitFiles {
	files, _ := renderBuilderCloudInit("")
	return files
}

// RenderBuilderCloudInitWithKey adds the short-lived operator key to the
// builder's explicit cloud-init user definition. This is required because a
// custom user-data document must not rely on Proxmox's generated sshkeys
// fragment to configure the pre-existing labadmin account.
func RenderBuilderCloudInitWithKey(operatorPublicKey string) (CloudInitFiles, error) {
	if err := ValidatePublicKey(operatorPublicKey); err != nil {
		return CloudInitFiles{}, err
	}
	return renderBuilderCloudInit(operatorPublicKey)
}

func renderBuilderCloudInit(operatorPublicKey string) (CloudInitFiles, error) {
	if operatorPublicKey != "" {
		if err := ValidatePublicKey(operatorPublicKey); err != nil {
			return CloudInitFiles{}, err
		}
	}
	userData := `#cloud-config
hostname: lab-builder-01
manage_etc_hosts: true
users:
  - default
  - name: labadmin
    shell: /bin/bash
    groups: [sudo]
    sudo: ["ALL=(root) NOPASSWD: /usr/local/sbin/boetticher-build"]
`
	if operatorPublicKey != "" {
		// JSON strings are valid YAML scalars and preserve an OpenSSH comment
		// without allowing it to alter the cloud-init document structure.
		userData += "    ssh_authorized_keys:\n      - " + strconv.Quote(operatorPublicKey) + "\n"
	}
	userData += `write_files:
  - path: /etc/apt/sources.list.d/boetticher-builder.sources
    permissions: '0644'
    content: |
      Types: deb
      URIs: https://snapshot.debian.org/archive/debian/20260327T000000Z/
      Suites: trixie
      Components: main
      Check-Valid-Until: no
  - path: /usr/local/sbin/boetticher-build
    permissions: '0755'
    content: |
      #!/bin/sh
      set -eu
      exec >/var/log/boetticher-build.log 2>&1
      export PATH=/usr/local/go/bin:$PATH
      test "$(/usr/local/go/bin/go version)" = "go version go1.26.5 linux/amd64"
      cd /home/labadmin/build
      export BOETTICHER_ARTIFACT_OUTPUT=/home/labadmin/build/generated/artifacts
      export BOETTICHER_EVIDENCE_ROOT=/home/labadmin/build
      export BOETTICHER_IMAGE_WORK=/var/lib/boetticher/image-work
      ./scripts/build-images.sh images
      ./scripts/scan-images.sh scan-images
      chown -R labadmin:labadmin /home/labadmin/build/generated/artifacts
      find /home/labadmin/build/generated/artifacts -type d -exec chmod 0755 {} +
      find /home/labadmin/build/generated/artifacts -type f -exec chmod 0644 {} +
      touch /home/labadmin/build/.qualification-complete
  - path: /etc/sudoers.d/boetticher-builder
    permissions: '0440'
    content: |
      labadmin ALL=(root) NOPASSWD: /usr/local/sbin/boetticher-build
runcmd:
  - [sh, -c, "set -eu; rm -f /etc/apt/sources.list /etc/apt/sources.list.d/debian.sources; apt-get -o Acquire::Check-Valid-Until=false update; DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends ca-certificates curl jq libguestfs-tools mmdebstrap openssh-server qemu-guest-agent qemu-utils sudo tar zstd"]
  - [sh, -c, "set -eu; archive=/tmp/go1.26.5.linux-amd64.tar.gz; curl --fail --location --silent --show-error --output $archive https://go.dev/dl/go1.26.5.linux-amd64.tar.gz; printf '%s  %s\\n' 5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053 $archive | sha256sum --check --status; rm -rf /usr/local/go; tar -C /usr/local -xzf $archive; printf '%s\\n' 'export PATH=/usr/local/go/bin:$PATH' > /etc/profile.d/boetticher-go.sh; test \"$(/usr/local/go/bin/go version)\" = \"go version go1.26.5 linux/amd64\"; rm -f $archive"]
  - [sh, -c, "set -eu; archive=/tmp/trivy_0.69.3_Linux-64bit.tar.gz; curl --fail --location --silent --show-error --output $archive https://github.com/aquasecurity/trivy/releases/download/v0.69.3/trivy_0.69.3_Linux-64bit.tar.gz; printf '%s  %s\\n' 1816b632dfe529869c740c0913e36bd1629cb7688bd5634f4a858c1d57c88b75 $archive | sha256sum --check --status; tar -xzf $archive -C /usr/local/bin trivy; chmod 0755 /usr/local/bin/trivy; rm -f $archive"]
  - [systemctl, enable, --now, qemu-guest-agent]
  - [touch, /run/boetticher-builder-ready]
`
	return CloudInitFiles{
		MetaData: "instance-id: boetticher-builder-0.3.30\nlocal-hostname: lab-builder-01\n",
		UserData: userData,
		NetworkConfig: fmt.Sprintf(`version: 2
ethernets:
  ens18:
    match:
      macaddress: %s
    dhcp4: true
`, model.BuilderMAC),
	}, nil
}

func cloudInitSnippetNames(vmid int) map[string]string {
	prefix := fmt.Sprintf("boetticher-%d", vmid)
	return map[string]string{"meta": prefix + "-meta.yaml", "user": prefix + "-user.yaml", "network": prefix + "-network.yaml"}
}

func cloudInitCICustom(vmid int) string {
	names := cloudInitSnippetNames(vmid)
	return fmt.Sprintf("user=local:snippets/%s,network=local:snippets/%s,meta=local:snippets/%s", names["user"], names["network"], names["meta"])
}
