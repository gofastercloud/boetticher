# Architecture

boetticher is a small, opinionated Proxmox distribution. The controller holds
the private site repository, SOPS/Age identity, CA signing authority, and
runtime state. Proxmox owns the host and user workloads; boetticher owns only
the declared platform resources.

## Fixed network

| VLAN | Zone | Network | Gateway | Purpose |
| --- | --- | --- | --- | --- |
| 5 | TRANSIT | `10.10.5.0/24` | `10.10.5.1` | Core routing and security edge |
| 10 | INFRA | `10.10.10.0/24` | `10.10.10.1` | shared platform infrastructure |
| 20 | SERVERS | `10.10.20.0/24` | `10.10.20.1` | platform and internal services |
| 30 | TRUSTED | `10.10.30.0/24` | `10.10.30.1` | trusted clients |
| 40 | SANDBOX | `10.10.40.0/24` | `10.10.40.1` | untrusted workloads |
| 99 | MGMT | `10.10.99.0/24` | `10.10.99.1` | infrastructure administration |

The internal namespace is `lab.home.arpa`. The platform identities are:

| Host | Address | Function |
| --- | --- | --- |
| `lab-proxmox-01` | `10.10.99.250` | Proxmox host |
| `lab-fw-01` | `.1` in all six zones | managed Debian gateway |
| `lab-dns-01` | `10.10.10.10` | PowerDNS, Blocky by default, Chrony |
| `lab-dns-02` | `10.10.10.11` | PowerDNS, Blocky by default, Chrony |
| `lab-monitor-01` | `10.10.10.20` | Zabbix and PostgreSQL |
| `lab-log-01` | `10.10.10.40` | Central systemd journal collector |
| `lab-portal-01` | `10.10.10.30` | generated portal |

The main service URLs are `https://monitor.lab.home.arpa` and
`https://portal.lab.home.arpa`. Proxmox is available at
`https://proxmox.lab.home.arpa:8006`.

## Managed gateway

```text
controller
    |
HOME / upstream
    |
Proxmox
  | vmbr0  -> wan0 (untagged)
  | vmbr1  -> transit0 (tag 5)
  |       -> infra0 (tag 10)
  |       -> servers0 (tag 20)
  |       -> trusted0 (tag 30)
  |       -> sandbox0 (tag 40)
  |       -> mgmt0 (tag 99)
  |
lab-fw-01, Debian VM
  nftables + Kea + SANDBOX DNS/NTP
```

The gateway receives one ordinary vNIC for each role. There is no VLAN trunk
and no VLAN subinterface inside `lab-fw-01`. Proxmox performs the VLAN
classification on the guest attachments. The guest is a routed firewall, not
a bridge.

The gateway is deliberately small: a qualified Debian 13 boetticher appliance
containing nftables, Kea DHCPv4/D2, minimal SANDBOX DNS/NTP services, SSH,
Chrony where needed, and Zabbix Agent 2. Its pinned Debian 13 GenericCloud
input is `debian-13-genericcloud-amd64-20260327-2429`; the input SHA-512 is
recorded in the model and verified during firewall image construction.
IPv4 forwarding stays disabled until a validated ruleset is installed.

## External gateway

External mode removes `lab-fw-01` from the platform. A second physical NIC is
required for `vmbr1`, and the operator’s appliance receives the 802.1Q trunk
with VLANs 5, 10, 20, 30, 40, and 99. The appliance provides the six `.1`
gateways, DHCP where required, NAT, and the published security policy.
boetticher generates the contract but does not inspect or manage the
appliance’s configuration.

## Platform services

DNS and NTP remain dual-host services. Blocky is the default client-facing
recursive/filtering provider and AdGuard Home is a supported typed alternative.
Kea-driven dynamic DNS updates travel to the PowerDNS authoritative primary
through authenticated RFC2136 and replicate to the secondary. TRUSTED and
SANDBOX use dynamic DHCP/DDNS modes, while SERVERS uses reservation-only
DHCP/DDNS. TRANSIT, INFRA, and MGMT use static assignments. The selected provider serves the fixed DNS/NTP
addresses from INFRA, while SANDBOX uses the gateway resolver and does not
receive the broad internal namespace.

The fixed network identities are intended for the next clean deployment or
rebuild. Existing installations are not automatically renumbered or live
migrated by this model change.

Zabbix monitors boetticher-owned platform hosts and services. The portal is a
static generated view of the model, documentation, and non-secret status; it
is not a second monitoring application.

## Determinism and ownership

The canonical model revision is a SHA-256 digest of the normalized site model.
It drives Proxmox, nftables, Kea, DNS, Ansible, Zabbix, SSH, portal, backup, and
verification projections. Timestamps and live evidence are excluded from the
digest. Unknown user guests and user-created service objects remain outside
boetticher ownership.
