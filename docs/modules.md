---
layout: default
title: Modules
section: modules
description: The capability-first Module boundary.
---

# Modules

Modules are operator-visible capabilities deployed onto or configured for the
Host. They are not a generic plugin system, arbitrary workloads, or a second
orchestration layer.

## Capability-first grammar

The public Module grammar has one normal third-level namespace:

```text
boetticher module <capability> <action> [flags]
```

Examples of the intended shape are:

```text
boetticher module firewall status
boetticher module firewall add-rule
boetticher module dhcp status
boetticher module dhcp add-reservation
boetticher module dns status
boetticher module dns add-record
boetticher module ntp status
boetticher module vpn status
boetticher module monitoring status
boetticher module statuspage add-check
boetticher module printer status
```

These examples document the grammar and operator intent. They do not enable
speculative capability implementation in Phase 3D.

## Capability, provider, runtime

Keep these concepts separate:

| Concept | Meaning | Examples |
| --- | --- | --- |
| Capability | What the operator manages | firewall, DHCP, DNS, NTP, VPN, monitoring, status page, printer |
| Provider | Software or appliance implementing a capability | gateway appliance, DNS resolver, monitoring service, status-page server |
| Runtime | Where the provider executes | a gateway VM, a monitoring VM/LXC, or the Controller |

The operator manages `module dns`, not `module unbound`; `module statuspage`,
not `module gatus`; and `module vpn`, not `module airvpn`. A provider can
implement several capabilities, and several capabilities can share one runtime.
Provider choice remains an implementation detail unless the provider itself is
genuinely the operator-managed product.

## Controller peripherals

Blinkt, StreamDeck, display, and kiosk hardware are Controller implementation
details. They do not become `module blinkt`, `module streamdeck`, or `module
display`. A physical device, daemon, VM, container, or third-party product is
not automatically a Module.

## Lifecycle boundary

Host configuration is established first with:

```text
boetticher host apply
boetticher host status
```

Host apply owns the Proxmox OS baseline, storage, and virtual networking. It
does not deploy Modules. When Module implementations are added, each must
choose a capability name, define its bounded action surface, preserve exact
ownership, and remain separate from Host lifecycle and Controller peripherals.
