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
The current reference implementation is a Raspberry Pi. Blinkt, StreamDeck,
display, and kiosk behavior remain Controller implementation details; none is a
Host Module namespace.

The Controller does not need a Host selector in the supported single-Host UX.
Multi-Host support is deliberately not implemented in this phase.

The Controller's fixed Blinkt layout is
`CTL HOST FW VPN TAILNET NET CTRL-UPDATES HOST-UPDATES`.
It is rendered by the local status daemon as a lightweight convenience; it is
not a monitoring or qualification system. Blinkt, StreamDeck, display, and
kiosk behavior remain Controller implementation details rather than Module
namespaces.

The Controller performs its 60-second Internet connectivity check and its
hourly full speedtest from the enrolled Proxmox Host over the existing strict
SSH relationship. The speedtest helper is a one-shot Host binary installed by
Host apply; the status daemon never installs packages or changes Host state.
Controller and Host update indicators inspect existing local/cached APT state
read-only. Controller reboot-required state remains separate from Host reboot
state. The Controller status daemon and Host helper are always installed by
their standard setup flows; Blinkt and StreamDeck remain optional peripherals
whose absence does not block setup.
If a StreamDeck is present on the Controller, the shared status daemon owns it
alongside Blinkt and exposes detailed read-only Host and guest telemetry.

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

The six VLAN numbers are Host configuration. The Phase 4A firewall capability
consumes this substrate and provides the virtual gateways and IPv4 policy; it
does not create or repair `vmbr1`.
Physical LAB networking is Host-owned and remains outside the Module namespace.
The current reference architecture is IPv4-only;
IPv6 forwarding and security policy are reserved for explicit future
firewall/network Module work rather than inferred from the internal vmbr1
regression.

The accepted reference physical clients are the Controller Pi
`dc:a6:32:e9:dd:82` with the permanent SERVERS reservation
`10.10.20.10` (`lab-companion.lab.home.arpa`) and the observed SANDBOX MacBook
lease `10.10.40.181`. These are evidence of the current installation binding,
not reusable fixture identities.

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
The boot disk, mounted or guest-used disks, foreign LVM, and ambiguous layouts
are protected or rejected.

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
recovery access. Rebuild uses `host enroll`, `host apply`, and `host status`.

## Modules: capability, provider, runtime

A Module is something the operator manages. A provider is software that
implements one or more capabilities. A runtime is where that provider executes.
They are separate concepts:

| Concept | Example |
| --- | --- |
| Capability | `firewall`, `dhcp`, `dns`, `vpn`, `monitoring`, `statuspage` |
| Provider | gateway appliance, DNS resolver, monitoring service, status-page server |
| Runtime | gateway VM, monitoring VM/LXC, or the Controller |

The public grammar is capability-first:

```text
boetticher module <capability> <action> [flags]
```

Phase 4A operator actions are `module firewall plan`, `apply`, `status`,
`reboot`, `test`, and `teardown`. OpenWrt implements this capability but remains
an internal provider detail. `test --plan` is read-only; `test --yes` runs the
fixed routed IPv4 suite against the existing provider; and
`test --cleanup-only --yes` removes only recognised temporary namespace/veth
leftovers without provider credentials. The suite is operational acceptance,
not `status`: it uses six temporary LAB namespaces and fixed gateway, egress,
inter-zone, HOME, and administration journeys, then requires exact cleanup.
The existing status monitor consumes the same native capability status facts
for the fixed `FW`, `VPN`, and `TAILNET` slots. Unconfigured client services
are off rather than permanent faults; configured-but-unavailable services are
failed. VPN, physical trunking, and
external-switch management are later phases.

Proxmox owns operator workloads. Boetticher never adopts, imports, or deletes
unknown guests, volumes, or network devices merely because a name or address
looks familiar.
