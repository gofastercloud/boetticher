# boetticher

**A small, opinionated Proxmox platform for a secure homelab.**

> **Status: pre-alpha.** The architecture and offline pieces are in place, but the first real installation still needs to be tried on a clean test host. Don’t use it on anything you can’t recover.

[![CI](https://github.com/gofastercloud/boetticher/actions/workflows/ci.yml/badge.svg)](https://github.com/gofastercloud/boetticher/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

boetticher turns a fresh x86 Proxmox host into a reproducible platform with OPNsense segmentation, Kea DHCP, dual DNS/NTP, internal PKI and mTLS, Zabbix observability, a generated portal, encrypted configuration, and a documented recovery path.

It is deliberately a distribution, not a configurable homelab framework and not a second Proxmox control plane. boetticher owns the platform foundation. Proxmox remains the user’s normal interface for user workloads.

## The architecture

```text
HOME / existing LAN
        |
     vmbr0                 Proxmox keeps its upstream recovery path
        |
  lab-proxmox-01
        |
  lab-fw-01 / OPNsense
        |
     vmbr1                 VLAN-aware internal bridge
        +-- VLAN 10 TRUSTED   10.10.10.0/24
        +-- VLAN 20 SERVERS   10.10.20.0/24
        +-- VLAN 50 SANDBOX   10.10.50.0/24
        `-- VLAN 99 MGMT      10.10.99.0/24

  lab-dns-01 + lab-dns-02    AdGuard Home, authoritative DNS, and NTP
  lab-monitor-01             Zabbix server, PostgreSQL, web, and mTLS
  lab-portal-01              generated static architecture and recovery view
```

OPNsense is the routing and inter-zone security boundary. Proxmox does not route between VLANs. The fixed V1 addresses, IPv4-only model, dual DNS/NTP design, storage profiles, and platform guest IDs are part of the product contract.

The internal namespace is `lab.home.arpa`. The generated platform records include `opnsense.lab.home.arpa`, `proxmox.lab.home.arpa`, `monitor.lab.home.arpa`, `portal.lab.home.arpa`, `dns01.lab.home.arpa`, and `dns02.lab.home.arpa`. The main web entry points are `https://proxmox.lab.home.arpa:8006`, `https://opnsense.lab.home.arpa`, `https://monitor.lab.home.arpa`, and `https://portal.lab.home.arpa`.

## What it promises

- A deterministic platform model and revision shared by OpenTofu, Ansible, OPNsense, Zabbix, SSH configuration, the portal, and verification output.
- Default-deny inter-zone policy with an Internet-only SANDBOX zone and restricted MGMT zone.
- DHCP-driven, zone-qualified dynamic DNS without adopting the workload that received the lease.
- SOPS-encrypted secrets with an Age identity kept outside Git and an explicit recovery-copy gate.
- A forwarding-only Proxmox SSH bastion that works from the HOME side even when internal DNS or a physical trunk is unavailable.
- Conservative physical NIC discovery: one NIC is supported, one additional unambiguous NIC can become the trunk, and ambiguous systems require operator selection.
- A portal that documents the deployed model and current status without becoming a second monitoring product.

## Requirements

- Fresh supported Proxmox VE x86 installation with node name `lab-proxmox-01`. The first supported Proxmox release will be recorded after a clean installation has been tried; this source tree does not imply that every PVE release works.
- Minimum host shape for the foundation: 4 logical CPU threads, 16 GiB RAM, and 128 GiB usable storage. 4+ cores, 32 GiB RAM, and 256 GiB or more is a much friendlier size for user workloads.
- One physical Ethernet NIC minimum. A second NIC and managed 802.1Q switch are recommended for physical VLAN breakout, but `vmbr1` may remain virtual-only.
- Controller: macOS arm64/amd64 or Linux arm64/amd64. The controller is a separate operator machine; do not run the V1 workflow on the target Proxmox host. Native Windows is out of scope; WSL2 is only supported if separately tested.
- Controller tools: Go matching `go.mod`, `ssh`, `ssh-keyscan`, `age-keygen`, `sops`, OpenTofu, and Ansible Core. `boetticher preflight` validates versions before mutation.
- OPNsense 26.7.2_2 at the exact qualified patch recorded in `site.yml`; later 26.7 patches require explicit boetticher qualification.
- Zabbix 7.0 LTS: full upstream support through June 2027 and limited support through June 2029.
- Either the single-disk or dedicated-data-disk storage profile.

## Quickstart

From a fresh controller and Proxmox HOME-side DHCP address:

```sh
boetticher init --site-dir my-boetticher
boetticher bootstrap-endpoint set PROXMOX_HOME_ADDRESS --site my-boetticher
boetticher preflight --site my-boetticher
boetticher bootstrap --site my-boetticher --opnsense-iso VERIFIED_ISO --recovery-confirmed
boetticher provision --site my-boetticher
boetticher converge --site my-boetticher
boetticher ssh-config --site my-boetticher --install-include
boetticher verify --site my-boetticher
boetticher access --site my-boetticher
```

Keep the independent recovery copy of the Age identity before destructive bootstrap proceeds. The private identity never belongs in Git. The initial Proxmox trust transition installs the operator key, creates the normal administrator and forwarding-only `lab-jump` identity, creates scoped API credentials, hands them directly to SOPS, and retires routine use of the initial bootstrap path.

Physical NIC discovery is conservative. With one NIC, the supported result is `virtual-only`. With exactly one additional clean Ethernet NIC, bootstrap can attach it to `vmbr1` after displaying the proposed mapping. With multiple possible trunk candidates, select one explicitly. A disconnected but otherwise clean trunk NIC is valid.

The source build has local contracts and tests for the bootstrap sequence. The first real installation still needs to try unattended OPNsense setup, the interface/address transition, dynamic DNS replication, physical NIC changes, and the negative network journeys on a clean host.

## Access and ownership

The normal path is:

```text
operator on HOME
        |
        +-- ssh proxmox  -> lab-proxmox-01
                              |
                              `-- ProxyJump lab-bastion -> internal hosts
```

Useful commands after convergence include `ssh dns01`, `ssh monitor`, `ssh portal`, and `boetticher access`. Generated SSH configuration uses fixed internal IPs, canonical `HostKeyAlias` values, the modelled destination allow-list, and normal host-key verification.

boetticher manages only declared platform resources. User workloads remain user-owned:

```text
Create VM/LXC in Proxmox
  -> attach its NIC to vmbr1
  -> choose VLAN 10, 20, 50, or justified VLAN 99
  -> use DHCP where appropriate
  -> boot
```

There is intentionally no generic `boetticher vm`, `boetticher lxc`, or `boetticher workload` lifecycle command. Use the Proxmox UI, `qm`, `pct`, OpenTofu, Ansible, Pulumi, or another tool for arbitrary workloads. See [docs/platform-ownership.md](docs/platform-ownership.md).

## Documentation

Start with [the architecture guide](docs/architecture.md), [the security model](docs/security-model.md), and [installation](docs/installation.md). The documentation is organised by operator task:

- [Networking](docs/networking/): VLANs, switch trunks, physical NIC discovery, DHCP/DNS/NTP, and dynamic DNS.
- [Access](docs/access/): the Proxmox bastion, client certificates, and documented Tailscale, Cloudflare, and WireGuard integration patterns.
- [Workloads](docs/workloads/): adding user-owned guests and optionally onboarding their own Zabbix agent.
- [Storage and recovery](docs/storage/): storage profiles, backup ownership, and recovery runbooks.
- [Operations](docs/operations.md) and [commands](docs/commands.md): the day-to-day CLI surface.
- [Troubleshooting](docs/troubleshooting.md): what to check when something goes wrong.
- [First installation](docs/hardware-test-checklist.md): a practical checklist for trying the platform on real hardware.

`lab-portal-01` renders this same release documentation alongside the installation-specific model and non-secret status information. It is passive static HTML; Zabbix owns live telemetry.

## Development

```sh
make ci
```

This runs Go formatting checks, tests, vet, build, OpenTofu formatting/validation, Ansible syntax validation, and whitespace checks. See [CONTRIBUTING.md](CONTRIBUTING.md) and [agents.md](agents.md) for the project conventions.

## Scope and non-goals

V1 is a single-Proxmox-host platform. It is not HA, IPv6-ready, an arbitrary network/address/storage framework, or a managed remote-access provider. Dual DNS is service redundancy, not host redundancy. Same-disk backups are not disaster recovery. Tailscale, Cloudflare, and WireGuard are documented integration patterns, not core V1 modules.

## License and acknowledgements

boetticher is released under the [Apache License 2.0](LICENSE). The project configures and integrates other open-source systems; it does not relicense or claim ownership of them. See [NOTICE](NOTICE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), especially the acknowledgements for the Proxmox and OPNsense projects and their maintainers.

boetticher is an independent project and is not affiliated with, sponsored by, or endorsed by Proxmox Server Solutions GmbH, the Proxmox project, Deciso B.V., or the OPNsense project.
