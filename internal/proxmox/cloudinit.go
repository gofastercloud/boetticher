package proxmox

import (
	"fmt"
	"strings"
)

type CloudInitFiles struct {
	MetaData      string
	UserData      string
	NetworkConfig string
}

// RenderFirewallCloudInit creates only first-boot transport state. Runtime
// firewall policy, DHCP scopes, and forwarding remain deployment-derived.
func RenderFirewallCloudInit(guest GuestPlan) (CloudInitFiles, error) {
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
	return CloudInitFiles{
		MetaData:      "instance-id: boetticher-firewall-1.0.0\nlocal-hostname: lab-fw-01\n",
		UserData:      "#cloud-config\nhostname: lab-fw-01\nmanage_etc_hosts: true\nusers:\n  - name: labadmin\n    shell: /bin/bash\n    groups: [sudo]\n    sudo: [\"ALL=(ALL) NOPASSWD:/usr/bin/systemctl, /usr/sbin/nft, /usr/sbin/kea-dhcp4, /usr/sbin/kea-dhcp-ddns\"]\nssh_pwauth: false\ndisable_root: true\nwrite_files:\n  - path: /etc/sysctl.d/boetticher-forwarding.conf\n    permissions: '0644'\n    content: |\n      net.ipv4.ip_forward=0\n      net.ipv6.conf.all.forwarding=0\n",
		NetworkConfig: network.String(),
	}, nil
}

// RenderBuilderCloudInit prepares the temporary public-input build host. It
// deliberately contains no operator key or site state; Proxmox supplies the
// short-lived SSH key through its ordinary cloud-init sshkeys parameter.
func RenderBuilderCloudInit() CloudInitFiles {
	return CloudInitFiles{
		MetaData: "instance-id: boetticher-builder-0.3.1\nlocal-hostname: lab-builder-01\n",
		UserData: `#cloud-config
hostname: lab-builder-01
manage_etc_hosts: true
package_update: true
packages:
  - ca-certificates
  - curl
  - golang-go
  - libguestfs-tools
  - mmdebstrap
  - openssh-server
  - qemu-guest-agent
  - qemu-utils
  - sudo
  - tar
  - zstd
write_files:
  - path: /usr/local/sbin/boetticher-build
    permissions: '0755'
    content: |
      #!/bin/sh
      set -eu
      cd /home/labadmin/build
      export BOETTICHER_ARTIFACT_OUTPUT=/home/labadmin/build/generated/artifacts
      export BOETTICHER_EVIDENCE_ROOT=/home/labadmin/build
      export BOETTICHER_IMAGE_WORK=/var/lib/boetticher/image-work
      ./scripts/build-images.sh images
      ./scripts/scan-images.sh scan-images
      touch /home/labadmin/build/.qualification-complete
  - path: /etc/sudoers.d/boetticher-builder
    permissions: '0440'
    content: |
      labadmin ALL=(root) NOPASSWD: /usr/local/sbin/boetticher-build
runcmd:
  - [sh, -c, "set -eu; archive=/tmp/trivy_0.69.3_Linux-64bit.tar.gz; curl --fail --location --silent --show-error --output $archive https://github.com/aquasecurity/trivy/releases/download/v0.69.3/trivy_0.69.3_Linux-64bit.tar.gz; printf '%s  %s\\n' 1816b632dfe529869c740c0913e36bd1629cb7688bd5634f4a858c1d57c88b75 $archive | sha256sum --check --status; tar -xzf $archive -C /usr/local/bin trivy; chmod 0755 /usr/local/bin/trivy; rm -f $archive"]
  - [systemctl, enable, --now, qemu-guest-agent]
`,
		NetworkConfig: `version: 2
ethernets:
  eth0:
    dhcp4: true
`,
	}
}

func cloudInitSnippetNames(vmid int) map[string]string {
	prefix := fmt.Sprintf("boetticher-%d", vmid)
	return map[string]string{"meta": prefix + "-meta.yaml", "user": prefix + "-user.yaml", "network": prefix + "-network.yaml"}
}

func cloudInitCICustom(vmid int) string {
	names := cloudInitSnippetNames(vmid)
	return fmt.Sprintf("user=local:snippets/%s,network=local:snippets/%s,meta=local:snippets/%s", names["user"], names["network"], names["meta"])
}
