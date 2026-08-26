# Installation

boetticher runs from a separate macOS or Linux controller and builds a small
platform on a fresh Proxmox host. The controller holds the private site
repository, Age identity, SOPS access, CA signing authority, and runtime state;
the Proxmox host is a target, not the controller.

Supported controllers are macOS arm64/amd64 and Linux arm64/amd64. Native
Windows is outside the v0.2 contract. One physical NIC is enough for managed
mode; a second NIC and managed VLAN switch provide physical access to the
internal zones. External-firewall mode requires both NICs.

## Create the site

```text
boetticher init --site-dir my-boetticher
```

Use `--external-firewall` to create the bring-your-own-firewall contract. The
default is the managed Debian gateway. The site repository contains desired
state, encrypted SOPS documents, and non-secret generated projections. The Age
private identity is outside Git at `~/.config/boetticher/age/identity.txt` (or
the explicit path supplied to `init`). Keep an independent recovery copy before
running a destructive bootstrap.

## Bootstrap

1. Install a supported fresh Proxmox host and connect to its HOME-side DHCP
   address.
2. Record that address with
   `boetticher bootstrap-endpoint set ADDRESS --site my-boetticher`.
3. Run `boetticher preflight --site my-boetticher --live`. It identifies the
   physical upstream interface conservatively and proposes a safe trunk
   candidate. Multiple candidates require `--trunk-interface`.
4. Run `boetticher ssh-config --site my-boetticher --force --install-include`.
5. Run `boetticher bootstrap --site my-boetticher --recovery-confirmed`.
   Dedicated storage also requires `--storage-confirmed` after reviewing the
   stable `/dev/disk/by-id/...` device.

Managed mode creates VM 100, `lab-fw-01`, as a Debian VM with one ordinary vNIC
for WAN and one Proxmox-tagged vNIC for each internal zone. The managed gateway
receives no 802.1Q trunk and has no VLAN subinterfaces.

External mode does not create VM 100. It requires a distinct physical vmbr1
trunk and publishes `generated/network/external-firewall-contract.md`. The
external appliance, DHCP, and its own recovery remain operator-owned.

## Deploy the platform

```text
boetticher deploy --site my-boetticher
boetticher verify --site my-boetticher
boetticher doctor --site my-boetticher
```

The managed path configures Debian networking, nftables, Kea, sandbox DNS/NTP,
DNS/NTP guests, Zabbix, the portal, PKI certificates, and platform backups.
The external path configures the boetticher-owned platform and leaves the
firewall appliance alone.

See [the external firewall contract](networking/external-firewall.md),
[storage](storage/dedicated-data-disk.md), and the recovery guides for
the detailed operational paths.
