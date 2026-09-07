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
boetticher module firewall plan
boetticher module firewall status
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

These examples document the grammar and operator intent. The firewall
capability is the first Phase 4 implementation; the remaining examples remain
future capability contracts until their own phase is qualified.

## Phase 4A firewall capability

The supported Phase 4A lifecycle is:

```text
boetticher module firewall plan
boetticher module firewall apply
boetticher module firewall status
boetticher module firewall reboot --yes
boetticher module firewall test --plan
boetticher module firewall test --yes
boetticher module firewall test --cleanup-only --yes
boetticher module firewall teardown --plan
boetticher module firewall teardown --yes
```

The capability owns one provider appliance named `lab-firewall-01`, its exact
VM and disk, its six virtual IPv4 gateways, its reference firewall policy, and
ordinary Internet NAT. The current provider implementation is OpenWrt, but
OpenWrt is not a public Module namespace. The provider consumes the Host-owned
VLAN-aware `vmbr1`; it never creates, repairs, or re-owns that bridge.

Phase 4A configures IPv4 routing, inter-zone default-deny policy, and
Controller-only provider management. DHCP and DNS are deliberately not
configured. Provider state outside deterministic Boetticher-owned sections is
preserved. Repeating `apply` when the provider and owned state are correct is a
semantic no-op. `teardown --yes` removes only the exact firewall provider and
Controller-local provider credential/trust, preserving Host trust, storage,
`vmbr0`, `vmbr1`, and physical networking.

`module firewall test` tests the firewall already present; it never applies,
repairs, reboots, or tears it down. The fixed suite creates one temporary
network namespace and veth/access port per TRANSIT, INFRA, SERVERS, TRUSTED,
SANDBOX, and MGMT zone, with a static `.250-.254` address candidate and the
zone gateway as its default route. It covers gateway access, ordinary HTTPS
egress, the fixed directional TCP/UDP policy, HOME protection, and appliance
administration. It does not claim same-VLAN, physical-switch, Wi-Fi, guest
firewall, or IPv6 isolation. Expected outcomes are independent of the
renderer; transport, setup, listener, and target failures are not successful
deny results. The test cleans up on completion, failure, timeout, and
interruption; use `module firewall test --cleanup-only --yes` for recognised
leftovers. `--plan` is read-only and `--plan --yes` is rejected.

`module firewall teardown --plan` describes the exact provider, disk, and
Controller-local credential/trust state that would be removed without a
prompt. The acceptance rehearsal ends with `module firewall teardown --yes`
and no firewall deployed; a later `status` reports absence with a nonzero exit
and does not claim PASS.

The existing Controller status monitor maps the same native firewall status
command into the fixed `FW` Blinkt slot and the StreamDeck Host-detail view.
`DHCP/NTP` and `DNS` remain red error placeholders until those capability
checks are implemented;
they use the same in-memory status model and polling loop, with no additional
status database or scheduler.

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
