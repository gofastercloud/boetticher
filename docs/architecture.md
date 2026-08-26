# Architecture

boetticher is a small, opinionated Proxmox distribution. The controller holds
the private site repository, SOPS/Age identity, CA signing authority, and
runtime state. Proxmox owns the host and user workloads; boetticher owns only
the declared platform resources.

## Fixed network

| VLAN | Zone | Network | Gateway | Purpose |
| --- | --- | --- | --- | --- |
| 10 | TRUSTED | `10.10.10.0/24` | `10.10.10.1` | trusted clients |
| 20 | SERVERS | `10.10.20.0/24` | `10.10.20.1` | platform and internal services |
| 50 | SANDBOX | `10.10.50.0/24` | `10.10.50.1` | untrusted workloads |
| 99 | MGMT | `10.10.99.0/24` | `10.10.99.1` | infrastructure administration |

The internal namespace is `lab.home.arpa`. The platform identities are:

| Host | Address | Function |
| --- | --- | --- |
| `lab-proxmox-01` | `10.10.99.5` | Proxmox host |
| `lab-fw-01` | `10.10.99.1` | managed Debian gateway |
| `lab-dns-01` | `10.10.20.10` | PowerDNS, Blocky by default, Chrony |
| `lab-dns-02` | `10.10.20.11` | PowerDNS, Blocky by default, Chrony |
| `lab-monitor-01` | `10.10.20.20` | Zabbix and PostgreSQL |
| `lab-log-01` | `10.10.20.40` | Central systemd journal collector |
| `lab-portal-01` | `10.10.20.30` | generated portal |

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
  | vmbr1  -> trusted0 (tag 10)
  |       -> servers0 (tag 20)
  |       -> sandbox0 (tag 50)
  |       -> mgmt0 (tag 99)
  |
lab-fw-01, Debian VM
  nftables + Kea + SANDBOX DNS/NTP
```

The gateway receives one ordinary vNIC for each role. There is no VLAN trunk
and no VLAN subinterface inside `lab-fw-01`. Proxmox performs the VLAN
classification on the guest attachments. The guest is a routed firewall, not
a bridge.

The gateway is deliberately small: Debian 13, nftables, Kea DHCPv4/D2,
minimal SANDBOX DNS/NTP services, SSH, Chrony where needed, and Zabbix Agent 2.
The qualified cloud image is the pinned Debian 13 GenericCloud amd64 input
`debian-13-genericcloud-amd64-daily`; its SHA-512 is recorded in the model and
verified before firewall image customization.
IPv4 forwarding stays disabled until a validated ruleset is installed.

## External gateway

External mode removes `lab-fw-01` from the platform. A second physical NIC is
required for `vmbr1`, and the operator’s appliance receives the 802.1Q trunk
with VLANs 10, 20, 50, and 99. The appliance provides the four `.1` gateways,
DHCP, NAT, and the published security policy. boetticher generates the contract
but does not inspect or manage the appliance’s configuration.

## Platform services

DNS and NTP remain dual-host services. Blocky is the default client-facing
recursive/filtering provider and AdGuard Home is a supported typed alternative.
Kea-driven dynamic DNS updates travel to the PowerDNS authoritative primary
through authenticated RFC2136 and replicate to the secondary. The selected
provider serves TRUSTED, SERVERS, and MGMT; SANDBOX uses the gateway resolver
and does not receive the broad internal namespace.

Zabbix monitors boetticher-owned platform hosts and services. The portal is a
static generated view of the model, documentation, and non-secret status; it
is not a second monitoring application.

## Determinism and ownership

The canonical model revision is a SHA-256 digest of the normalized site model.
It drives Proxmox, nftables, Kea, DNS, Ansible, Zabbix, SSH, portal, backup, and
verification projections. Timestamps and live evidence are excluded from the
digest. Unknown user guests and user-created service objects remain outside
boetticher ownership.
