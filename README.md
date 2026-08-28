# boetticher

**Status: pre-alpha.** boetticher v0.3.34 has a typed module model and offline
contracts, but the appliance build and live installation still need
qualification. Do not use boetticher on a system you cannot recover.

boetticher is a small, opinionated Proxmox platform for a private lab. It
creates the platform foundation—network zones, DNS/NTP, PKI, Pulse Community monitoring, a static
portal, backups, and recovery metadata—from one deterministic site model.

It is not a generic Proxmox management tool. boetticher owns its declared
platform resources; Proxmox remains the owner of user workloads.

## Architecture

The default gateway is a small Debian VM running nftables and Kea. Proxmox
does the VLAN tagging, so the gateway receives ordinary interfaces rather than
an 802.1Q trunk.

```text
HOME / upstream
       |
     vmbr0
       |
    Proxmox
       |
  lab-fw-01 (Debian)
   nftables + Kea
       |
     vmbr1
       |
 VLAN 5 / 10 / 20 / 30 / 40 / 99
       |
 TRANSIT / INFRA / SERVERS / TRUSTED / SANDBOX / MGMT
```

The platform services are:

```text
lab-dns-01       10.10.10.10  PowerDNS, Blocky (AdGuard alternative), Chrony
lab-dns-02       10.10.10.11  PowerDNS, Blocky (AdGuard alternative), Chrony
lab-monitor-01   10.10.10.20  Pulse Community monitoring
lab-log-01       10.10.10.40  Central systemd journal collector
lab-portal-01    10.10.10.30  generated static documentation
```

Pulse reads Proxmox inventory and guest state through its dedicated API token.
A Pulse host agent is installed only on components carrying the generic
`monitoring-agent` tag; the default tag is on `lab-proxmox-01` for host CPU,
memory, temperature, and SMART telemetry. VM and LXC guests do not receive an
agent. The monitor UI remains `https://monitor.lab.home.arpa` behind the
platform HTTPS/mTLS boundary.

The fixed networks are VLAN 5 TRANSIT (`10.10.5.0/24`), VLAN 10 INFRA
(`10.10.10.0/24`), VLAN 20 SERVERS (`10.10.20.0/24`), VLAN 30 TRUSTED
(`10.10.30.0/24`), VLAN 40 SANDBOX (`10.10.40.0/24`), and VLAN 99 MGMT
(`10.10.99.0/24`). Every gateway owns `.1`; managed Proxmox uses
`10.10.99.5` on MGMT. v0.3 remains IPv4-only.

The platform resolves to Core plus the mandatory DNS/NTP module and the
default-on monitoring and managed firewall modules. Modules are built into the
boetticher release and emit declarations; Core owns privileged infrastructure
changes. There is no background controller or third-party module runtime.
Central logging is mandatory and uses bounded journald plus asynchronous mTLS
upload to `lab-log-01`. The default DNS provider is Blocky; set
`modules.dns.provider: adguard` to select the supported alternative.

## Two gateway modes

`managed` is the default. boetticher creates `lab-fw-01`, configures its WAN
interface and six fixed internal interfaces, renders the nftables policy, and
runs Kea, DDNS, and the SANDBOX DNS/NTP services. SERVERS uses reservation-only
DHCP with DDNS; TRUSTED and SANDBOX use their existing DHCP/DDNS modes. The
gateway owns `.1` in TRANSIT, INFRA, SERVERS, TRUSTED, SANDBOX, and MGMT.

`external` is bring-your-own firewall mode. boetticher creates no firewall VM,
does not manage the appliance, and publishes a deterministic contract for the
operator to configure. It requires a separately selected physical trunk NIC
carrying VLANs 5, 10, 20, 30, 40, and 99; the operator firewall owns `.1` in
each subnet, and bootstrap never silently selects even a sole eligible NIC.
See
[`docs/networking/external-firewall.md`](docs/networking/external-firewall.md).

This network layout is for the next clean deployment/rebuild. Existing
installations require an operator-planned rebuild or migration; this tranche
does not automatically renumber live hosts or guests.

## Requirements

- A fresh supported Proxmox VE installation on amd64 hardware.
- A separate macOS or Linux controller with Go, SSH, Age, SOPS, OpenTofu, and
  Ansible Core.
- One physical Ethernet NIC is enough for managed virtual-only operation. A
  second NIC and managed VLAN switch are needed for a physical trunk; they are
  mandatory in external-firewall mode.
- Either the single-disk or dedicated-data-disk storage profile.
- Pulse Community 6.1.2 and the pinned Debian 13 appliance definitions are the v0.3
  qualification targets (`debian-13-genericcloud-amd64-20260327-2429`).

## Quickstart

From the controller and the Proxmox HOME-side DHCP address:

```sh
boetticher init --site-dir my-boetticher
boetticher bootstrap-endpoint set 192.0.2.10 --site my-boetticher
boetticher preflight --site my-boetticher --live
boetticher bootstrap --site my-boetticher --recovery-confirmed --proxmox-ca /path/to/pve-root-ca.pem
boetticher deploy --site my-boetticher --dry-run --proxmox-ca /path/to/pve-root-ca.pem
boetticher deploy --site my-boetticher --proxmox-ca /path/to/pve-root-ca.pem
boetticher ssh-config --site my-boetticher --install-include
boetticher verify --site my-boetticher --proxmox-ca /path/to/pve-root-ca.pem
boetticher doctor --site my-boetticher --live --proxmox-ca /path/to/pve-root-ca.pem
```

Supply `--confirm` only when the deployment plan identifies a supported
destructive action that explicitly requires confirmation.

For an external firewall, start with:

```sh
boetticher init --external-firewall
```

Then configure the physical trunk according to the generated external
firewall contract before running the live workflow.

## Ownership and access

boetticher owns the platform guests, bridges and VLAN policy it declares, the
managed gateway when selected, platform DNS/NTP, PKI, Pulse monitoring state, backups,
portal output, and verification metadata. Unknown Proxmox guests remain user-
managed and are never imported, changed, deleted, or backed up by boetticher.
Pulse may display API-visible user guests without adopting them into the
boetticher model.

Proxmox is the normal SSH bastion. The controller reaches Proxmox over the
HOME network, then uses the forwarding-only `lab-bastion` path to reach
managed internal hosts. Generated SSH configuration keeps host-key checking
and canonical host identities intact.

Useful commands include `boetticher module list`, `boetticher module plan
monitoring`, `boetticher config validate`, `boetticher firewall show`,
`boetticher dhcp status`, `boetticher doctor`, and `boetticher portal build`.
These inspect or deploy the platform model; they are not a generic firewall,
guest-management, or application-management interface.

## Documentation

Start with [`docs/installation.md`](docs/installation.md), then see the
architecture, security, networking, storage, access, recovery, and workload
guides under [`docs/`](docs/). The generated portal renders the same release
documentation.

## Limitations

v0.3 is a single-node, pre-alpha platform. It is not HA, does not support
IPv6, multi-node Proxmox, generic VM/LXC lifecycle management, managed VPN or
remote-access products, arbitrary storage or network layouts, or managed
external firewall vendors. Local backups are useful for recovery but are not
independent disaster recovery.

## License and acknowledgements

boetticher is released under the [Apache License 2.0](LICENSE). It is an
independent project and is not affiliated with or endorsed by Proxmox Server
Solutions GmbH or the Proxmox project. See [NOTICE](NOTICE) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for current runtime
attributions, including the Proxmox project and its maintainers.
