# Architecture

boetticher is a small, opinionated infrastructure distribution rather than a configurable homelab framework. It provides a reproducible Proxmox platform with OPNsense segmentation, secure DHCP/DNS/NTP, internal PKI/mTLS, Zabbix observability, a generated portal, encrypted configuration, and local recovery from a fresh x86 host.

## Fixed network

| VLAN | Zone | Network | Gateway | Purpose |
| --- | --- | --- | --- | --- |
| 10 | TRUSTED | `10.10.10.0/24` | `10.10.10.1` | trusted personal clients |
| 20 | SERVERS | `10.10.20.0/24` | `10.10.20.1` | internal services |
| 50 | SANDBOX | `10.10.50.0/24` | `10.10.50.1` | untrusted/test clients |
| 99 | MGMT | `10.10.99.0/24` | `10.10.99.1` | infrastructure administration |

The fixed core addresses are `lab-fw-01` at `10.10.99.1`, Proxmox at `10.10.99.5`, DNS at `10.10.20.10` and `10.10.20.11`, monitor at `10.10.99.20`, and portal at `10.10.20.30`. IPv6 is deliberately unsupported in V1.

OPNsense owns routing, NAT, inter-zone firewalling, DHCP, SANDBOX DNS/NTP, and network aliases. Proxmox does not perform inter-VLAN routing. The firewall VM has a HOME-side WAN device on `vmbr0` and an untagged internal trunk device on VLAN-aware `vmbr1`; OPNsense owns the VLAN subinterfaces on that trunk.

`vmbr1` initially has no physical member. This is virtual-only bootstrap mode. A second NIC and managed switch can later carry the same tagged trunk without changing the logical model.

Physical NICs are installation-specific bindings, not logical architecture. Preflight identifies the upstream device from the active bridge/address/default-route/bootstrap evidence. It auto-proposes exactly one otherwise-unused physical Ethernet interface as the trunk, accepts an explicit selection when several remain, and stops with `HOLD` when evidence is ambiguous. Stable MAC/PCI identity is persisted separately from the current Linux interface name.

## Foundation guests

The base product is Proxmox plus `lab-fw-01`, `lab-dns-01`, `lab-dns-02`, `lab-monitor-01`, and `lab-portal-01`. The portal is static generated HTML served by nginx; it has no database, CMS, accounts, API credentials, SOPS identity, or Git write access. Zabbix owns live telemetry.

The canonical model and its SHA-256 revision drive Proxmox desired state, OPNsense policy, Kea configuration, Ansible inventory, Zabbix provisioning, SSH aliases/bastion policy, portal pages, and verification artifacts. Timestamps and live evidence are not included in the model digest.

boetticher owns only declared platform resources. It never adopts arbitrary Proxmox guests, bridges, bonds, VLANs, routes, SDN objects, Zabbix objects, or backup jobs. User workloads inherit the zone policy without entering the platform model.
