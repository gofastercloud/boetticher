# Installation

boetticher runs from a separate macOS or Linux controller and builds a small
platform on a fresh Proxmox host. The controller holds the private site
repository, Age identity, SOPS access, CA signing authority, and runtime state;
the Proxmox host is a target, not the controller.

Supported controllers are macOS arm64/amd64 and Linux arm64/amd64. Native
Windows is outside the v0.3 contract. One physical NIC is enough for managed
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
   physical upstream interface conservatively and reports safe trunk
   candidates. Managed mode defaults to virtual-only: spare NICs remain
   unclaimed until the operator explicitly attaches a selected trunk. External
   mode requires an explicitly selected physical trunk, even when only one
   eligible NIC is discovered; use `--trunk-interface` for that selection.
4. Run `boetticher ssh-config --site my-boetticher --force --install-include`.
5. Supply the Proxmox cluster CA PEM (for example, a securely copied
   `/etc/pve/pve-root-ca.pem` from the target) and run
   `boetticher bootstrap --site my-boetticher --recovery-confirmed
   --proxmox-ca /path/to/pve-root-ca.pem`. The CA is verified before
   bootstrap creates the API token. `--insecure` is not part of the supported
   qualification path.
   Dedicated storage also requires `--storage-confirmed` after reviewing the
   stable `/dev/disk/by-id/...` device.

Managed mode prepares the host and artifact substrate during bootstrap. The
first `deploy` creates VM 100, `lab-fw-01`, as the qualified boetticher Debian
firewall appliance with one ordinary vNIC for WAN and one Proxmox-tagged vNIC
for each internal zone. The managed gateway receives no 802.1Q trunk and has
no VLAN subinterfaces.

Bootstrap also establishes a temporary root SSH deployment window on the
Proxmox host. Managed guest first boot preserves the injected root key for the
same window and installs the `labadmin` key without granting general `labadmin`
sudo authority; the managed firewall image retains only fixed, read-only
inspection helpers.
The deployment playbook connects as root without Ansible `become`. Successful
convergence removes the root key, disables the host root SSH allowance, and
locks the root password. If deployment fails before cleanup, retry through the
same temporary root path; cleanup failure is a hold requiring bootstrap or
recovery authority.

External mode does not create VM 100. It requires a distinct physical vmbr1
trunk and publishes `generated/network/external-firewall-contract.md`. The
external appliance, DHCP, and its own recovery remain operator-owned.

## Deploy the platform

```text
boetticher deploy --site my-boetticher --proxmox-ca /path/to/pve-root-ca.pem
boetticher verify --site my-boetticher --proxmox-ca /path/to/pve-root-ca.pem
boetticher doctor --site my-boetticher --proxmox-ca /path/to/pve-root-ca.pem
```

`deploy` is the only public command that applies the complete desired
platform. `bootstrap` prepares the host and build inputs; module configuration,
guest identities, artifacts, services, backups, and shared policy are applied
through `deploy`.

The managed path configures Debian networking, nftables, Kea, sandbox DNS/NTP,
DNS/NTP guests, the Pulse monitoring appliance, the tagged Pulse host agent,
the portal, PKI certificates, and platform backups. The default agent target is
the Proxmox host; guest agents require an explicit `monitoring-agent` tag on a
declared managed component.
The external path configures the boetticher-owned platform and leaves the
firewall appliance alone.

See [the external firewall contract](networking/external-firewall.md),
[storage](storage/dedicated-data-disk.md), and the recovery guides for
the detailed operational paths.
