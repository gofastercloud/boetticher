---
layout: default
title: The lab
section: lab
description: The Boetticher Controller, Host, and Module boundary.
---

# Your lab, demystified

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

The Controller's fixed Blinkt layout is `CTL HOST FW DNS DHCP NET CFG RBT`.
It is rendered by the local status daemon as a lightweight convenience; it is
not a monitoring or qualification system. Blinkt, StreamDeck, display, and
kiosk behavior remain Controller implementation details rather than Module
namespaces.

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

## Fixed virtual topology

HOME management remains on `vmbr0`. Host apply configures a virtual-only,
VLAN-aware `vmbr1` with no Host address and no physical member. The current
semantic VLANs are:

| VLAN | Zone | Role |
| ---: | --- | --- |
| 5 | TRANSIT | Later transit capabilities |
| 10 | INFRA | Infrastructure services |
| 20 | SERVERS | Server workloads |
| 30 | TRUSTED | Trusted clients |
| 40 | SANDBOX | Isolated test/client traffic |
| 99 | MGMT | Management traffic |

The six VLAN numbers are Host configuration in this phase. They do not by
themselves claim firewall isolation, DHCP, DNS, or application behavior.
Physical LAB networking is a later Host configuration concern and remains
outside the Module namespace. The current reference architecture is IPv4-only;
IPv6 forwarding and security policy are reserved for explicit future
firewall/network Module work rather than inferred from the internal vmbr1
regression.

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
- physical LAB networking as `Not configured` until that Host concern exists;
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
| Capability | `firewall`, `dhcp`, `dns`, `ntp`, `vpn`, `monitoring`, `statuspage`, `printer` |
| Provider | gateway appliance, DNS resolver, monitoring service, status-page server |
| Runtime | gateway VM, monitoring VM/LXC, or the Controller |

The public grammar is capability-first:

```text
boetticher module <capability> <action> [flags]
```

For example, future operator actions may be `module firewall add-rule`,
`module dhcp add-reservation`, `module dns add-record`, or `module statuspage
add-check`. Provider-specific names do not become namespaces merely because
they are implementation choices. Phase 3D
documents this boundary without starting firewall or speculative Module
implementation.

Proxmox owns operator workloads. Boetticher never adopts, imports, or deletes
unknown guests, volumes, or network devices merely because a name or address
looks familiar.
