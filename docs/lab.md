---
layout: default
title: The lab
section: lab
description: The Boetticher Controller, Host, and Module boundary.
---

# Your lab, demystified

## Reference topology

The [logical reference-lab topology](images/network-topology.svg) separates
deployed logical services from observability/media rollout work. The
[physical wiring reference](images/physical-network.svg) shows the
operator-specified switch-port map, equipment, and cable colours. Each has an
editable source: [logical draw.io](images/network-topology.drawio) and
[physical draw.io](images/physical-network.drawio). These are concise IPv4 and
wiring views, not firewall-rule inventories, IPv6-isolation proof, complete
live-link audits, or deployment acceptance records. Status and current-address
labels are dated 9 September 2026.

Boetticher currently manages one Proxmox Host from one Controller. The Host is
the product object below the Controller; storage and networking are Host
configuration, not separate lifecycle objects.

```text
Controller
    |
    v
Proxmox Host
    |
    +-- Module <capability>
    +-- Module <capability>
    +-- Module <capability>
```

## Controller

The Controller runs Boetticher, keeps the persistent administrative identity,
stores `/etc/boetticher/controller.yml`, and owns its attached peripherals.
The current reference implementation is a Raspberry Pi.

The Controller does not need a Host selector in the supported single-Host UX.
Multi-Host support is deliberately not implemented.

The Controller's local status daemon owns the optional Blinkt and StreamDeck
and renders shared capability facts as a lightweight convenience, not a
monitoring or qualification system. Its connectivity and speedtest checks run
from the enrolled Host over the existing strict SSH relationship and never
change Host state. The layouts and states are described once, in the
[Controller guide](controller.html#status-daemon-and-peripherals). Blinkt,
StreamDeck, display, and kiosk behavior remain Controller implementation
details rather than Module namespaces.

## Host configuration

The Host configuration is stored in `/etc/boetticher/lab.yml`. It binds the
verified Proxmox address, root user, discovered node, repository policy, and
the operator-selected stable data disk. Native Proxmox state remains runtime
truth; transient interface indexes, routes, status results, evidence, and plan
digests are not persisted as desired state.

Host apply owns three focused internal concerns under one operator action:

1. the bounded Proxmox OS baseline and headless policy;
2. the dedicated data-storage layout; and
3. the internal VLAN-aware virtual bridge.

Each concern inspects native state first. Exact state is a no-op, safely absent
state can be created, recognized Boetticher-owned partial state can be resumed,
and conflicting or ambiguous state stops without mutation.

The baseline configures only the known Proxmox `no-subscription` repository
policy, required Host prerequisites, headless power behavior, and the
release-built Host speedtest helper. The same role explicitly enables and
starts the required Proxmox services (`pve-cluster`, `pvedaemon`, `pvestatd`,
and `pveproxy`) so they return after reboot. It never upgrades or reboots
Proxmox; see [Host maintenance](start.html#host-maintenance).

## Fixed physical topology

HOME management remains on `vmbr0`. The current Host binding uses a
VLAN-aware `vmbr1` with no untagged Host address or default gateway and the
verified `nic1` physical member restricted to tagged VLANs 5, 10, 20, 30, 40,
and 99. Proxmox management uses the tagged `vmbr1.99` interface at
`10.10.99.5/24`, without a default gateway. The current
semantic VLANs are:

| VLAN | Zone | Role |
| ---: | --- | --- |
| 5 | TRANSIT | Later transit capabilities |
| 10 | INFRA | Infrastructure services |
| 20 | SERVERS | Server workloads |
| 30 | TRUSTED | Trusted clients |
| 40 | SANDBOX | Isolated test/client traffic |
| 99 | MGMT | Management traffic |

The six VLAN numbers are Host configuration. The firewall capability
consumes this substrate and provides the virtual gateways and IPv4 policy; it
does not create or repair `vmbr1`.
Physical LAB networking is Host-owned and remains outside the Module namespace.
The current reference architecture is IPv4-only;
IPv6 forwarding and security policy are reserved for explicit future
firewall/network Module work rather than inferred from the internal vmbr1
regression.

The reference topology includes a Controller on SERVERS and a client on
SANDBOX. Addresses, hostnames, MACs, and leases belong in private acceptance
records; public documentation deliberately leaves those site-specific values
out.

The physical member is an explicit Host binding. Select it once, by
interface name, and Host apply records its permanent MAC:

```sh
sudo boetticher host apply --physical-trunk nic1 --adopt-existing-network --yes
```

A later `--physical-trunk` that does not match the persisted binding is
refused. `host apply` adds an absent `vmbr1` stanza with VLAN awareness and no
untagged address or gateway, and adds the tagged `vmbr1.99` management
interface with LAB return routes via `10.10.99.1`. It never rewrites `vmbr0`,
changes the HOME address or default route, enables forwarding, or configures
DHCP, DNS, firewall, guests, or switches. A compatible existing bridge needs
`--adopt-existing-network`: it must be VLAN-aware with no configured
addresses, gateway, or unknown interface directives. Runtime IPv6 link-local
addresses alone are compatible; configured link-local, global IPv6, IPv4, and
gateway routes remain conflicts.

Boetticher owns `/etc/sysctl.d/70-boetticher-vmbr1.conf`, setting
`net.ipv6.conf.vmbr1.disable_ipv6=1`, and a vmbr1-only
`/etc/network/if-up.d/boetticher-vmbr1` hook that reapplies suppression after
bridge creation, including at boot (ifupdown2 script support must be enabled).
Existing unrelated files at either path are rejected. This disables Host IPv6
participation on vmbr1 without adding Ethernet filtering or globally disabling
IPv6. After configuration, and again after an approved Proxmox reboot,
`ip -6 addr show dev vmbr1` shows no address and
`sysctl net.ipv6.conf.vmbr1.disable_ipv6` equals `1`.

For the read-only `host status` health check, `vmbr1` is healthy when the link is
up, VLAN-aware, correctly configured, and has no Host L3 address or gateway.
The approved tagged physical member is required for the physical-trunk
installation. Unknown or mismatched physical bindings remain rejected by Host
apply.

## Dedicated storage

The dedicated-data-disk profile uses one exact `/dev/disk/by-id/` identity and
creates only the owned LVM-thin layout:

| Resource | Value |
| --- | --- |
| Volume group | `boetticher-vg` |
| Thin pool | `data` |
| Proxmox storage | `boetticher-data` |
| Content | `images`, `rootdir` |

`boetticher host plan-storage` is read-only. `host apply` requires the exact
stable `--data-disk` binding and `--yes` before erasing an eligible candidate.
The plan traces the running Proxmox root/LVM stack to protect the boot disk
and identifies candidates only through stable `/dev/disk/by-id` paths;
capacity, enumeration order, and `/dev/sdX` names are not identity. Only an
empty, uniquely identified disk is eligible. Mounted, partitioned,
LVM-backed, guest-used, Proxmox-used, changed, or ambiguous state fails
closed. Apply creates no filesystem or mount, moves no guests, and writes the
selected stable identity to `/etc/boetticher/lab.yml` only after successful
verification. A conflicting or partial layout is never wiped automatically.
Proxmox registers `boetticher-data` as an `lvmthin` store with
`images,rootdir` content.

During acceptance, run a small reversible Proxmox allocation smoke test on
`boetticher-data` without creating a guest. A Proxmox reboot is a separate
explicit approval; afterwards recheck the PV, VG, thin pool, storage
registration, guests, and management network. Independent Mac/root access
remains the recovery path if a storage step fails.

## Host status and recovery

`boetticher host status` is the single normal Host view. It reports:

- Host trust and enrollment;
- Host configuration;
- dedicated storage;
- the internal network;
- physical LAB networking through the verified tagged `nic1` Host binding;
- Module state; and
- overall Host readiness.

`boetticher host status --details` adds the node/version, guests, storage,
stable disks, LVM, mounts, interfaces, bridges, and routes. Status never
repairs state.

`boetticher host teardown --plan` previews exact removal. The destructive form
requires `--data-disk` matching the configured stable identity and `--yes`.
Teardown preserves Controller configuration, Controller SSH identity, imported
Host trust, Proxmox installation, boot disk, HOME management, and independent
recovery access. It removes, from dependent configuration to prerequisites,
only the exact Boetticher-owned vmbr1, its Host IPv6 suppression, the
`boetticher-data` registration and LVM layout, safely removable Host-baseline
files, and the enrollment, storage, and network selections in `lab.yml`.
Shared packages, unknown repository or power settings, guests, and unrelated
storage stop the operation. Afterwards `lab.yml` keeps the Proxmox address and
user, `host status` reports the intentional trust-only state, and `host apply`
directs the operator to `host enroll`. The operator journey is in
[Start here](start.html#host-teardown-and-rebuild).

## Modules: capability, provider, runtime

A Module is something the operator manages. A provider is software that
implements one or more capabilities. A runtime is where that provider executes.
They are separate concepts:

| Concept | Example |
| --- | --- |
| Capability | `firewall`, `dns`, `dhcp`, `vpn`, `tailnet`, `observability`, `monitoring`, `logging`, `statuspage`, `media` |
| Provider | gateway appliance, DNS resolver, subnet router, monitoring service, status-page server |
| Runtime | gateway VM, Tailnet LXC, monitoring LXC, media VM, or the Controller |

The public grammar is capability-first:

```text
boetticher module <capability> <action> [flags]
```

The firewall capability creates the shared gateway appliance and its six
virtual gateways; DNS, DHCP, and VPN are peer capabilities on that appliance.
Tailnet, observability, and media each own one fixed guest. Each capability's
ownership and lifecycle is described in [Modules](modules.html); the firewall
contract and packet suite are in
[Firewall capability](networking/firewall-capability.html), and the DNS/DHCP
contract is in [Client services](networking/client-services.html). Capability
status feeds the Controller display; see the
[Controller guide](controller.html#status-daemon-and-peripherals).

Physical trunking is Host configuration (`host apply --physical-trunk`), not a
Module. External-switch management is not implemented.

Proxmox owns operator workloads. Boetticher never adopts, imports, or deletes
unknown guests, volumes, or network devices merely because a name or address
looks familiar.
