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

Implemented Phase 4 capability examples are:

```text
boetticher module firewall plan
boetticher module firewall status
boetticher module dhcp status
boetticher module dhcp add-reservation
boetticher module dns status
boetticher module dns add-record
boetticher module tailnet status
boetticher module tailnet apply --auth-key-file /secure/path/key --yes
boetticher module vpn status
boetticher module monitoring status
boetticher module statuspage add-check
boetticher module printer status
```

DHCP-derived DNS and client-facing NTP are supporting behaviour of the peer
`dhcp` and `dns` capabilities, not standalone capabilities. VPN dispatch,
provider reconciliation, fail-closed policy, and Controller-daemon observation
are implemented; remote and physical acceptance remain separate gates.

## Phase 4D Tailnet capability

`module tailnet` owns the single fixed subnet-router guest `lab-tailnet-01`
(VMID 200) and its exact TRANSIT reservation (`10.10.5.10`, MAC
`02:00:00:00:05:10`). Apply requires enabled DNS and DHCP, the exact Host
substrate, and the pinned Host-native image builder. An auth key is read only
after approval from the private regular file supplied with `--auth-key-file`;
it is streamed to the guest and never saved in intent or logs. Repeating apply
after native runtime, provider, and intent agreement is a no-op.

The guest advertises `10.10.0.0/16` with SNAT enabled, disables exit-node,
accept-routes, accept-DNS, and SSH, and applies a fail-closed nftables policy.
Native status verifies TUN, backend state, exact preferences, route approval,
package version, persistent assets, and the loaded policy. Tailnet status is
local runtime evidence; remote peer reachability, split-DNS grants, packet
journeys, and physical isolation require separate acceptance. Key expiry or
machine approval attention is recoverable by rerunning apply with a current
operator-approved key. Phase 4D local runtime is qualified; remote and physical
acceptance remain separate gates.

## 4E network closeout state

The fixed Firewall, DHCP/DNS, VPN, and Tailnet capability boundary now feeds
the status daemon through ordinary internal calls. The daemon maps VPN and DNS
facts into the existing snapshot and StreamDeck slots, keeps module collection
single-flight off the event loop, and preserves bounded cancellation. A
configured VPN with unverified egress remains distinct from a failed or
unconfigured VPN.

Native observations and regressions are bounded: VPN failure is not `OFF`, and
healthy DHCP plus failed DNS is not `healthy`. Keep the Blinkt mapping fixed at
eight pixels: `CTL HOST FW VPN TAILNET NET CTRL-UPDATES HOST-UPDATES`.
DHCP/NTP detail remains in StreamDeck host detail and CLI status. Keep the
existing StreamDeck home `FW`, `VPN`, `TAILNET`, `SCROLL`, and `REFRESH` area;
use its existing detail navigation for DHCP/NTP and DNS. Add no display stack,
hardware, or framework.

Keep cleanup narrow: delete only proven obsolete reachable network callers and
docs, preserve security tests, and add regressions for changed behaviour. NET
remains a Host HOME observation; VPN availability does not prove protected
client enforcement. Physical navigation, USB reconnect, and overlay expiry
returning fresh state remain NOT TESTED; fix only observed faults.

The reference physical path now uses exact `nic1` ownership on `vmbr1`, with
tagged VLAN 20 (SERVERS) and VLAN 40 (SANDBOX) only and untagged ingress
rejected. Current lease evidence is Pi `10.10.20.106` on SERVERS and the
MacBook `10.10.40.181` on SANDBOX; HOME remains on `vmbr0`. Remote Tailnet,
packet, physical USB, and the disposable protected VPN-client journey remain
separate acceptance gates and are reported as `NOT TESTED` or `HOLD` until
their exact journeys execute.

Recovery retains protected off-component config, identities, and AirVPN/Tailnet
credentials, or documents deliberate reprovision; leases are disposable. Use
the existing independent Controller/Host management path, with no backup
platform or Host teardown.

Application networking keeps ordinary existing calls with narrow ingress,
egress, and identity names; do not add a generic schema. Use owned-domain
HTTPS with DNS-01 automated renewal, the first Stage 5 dashboard, and an
application backup before Stage 6. Stage 5 covers monitoring, logging, and
statuspage work; add no CA or proxy platform now.

Defer new network modules, an aggregate coordinator, CA/SSO/proxy platforms,
observability implementation, and switch automation. The existing management
route remains the boundary.

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
Controller-only provider management. Provider state outside deterministic
Boetticher-owned sections is
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

Phase 4B adds `module dns` and `module dhcp` as peer capabilities sharing this
appliance. DHCP-derived DNS and client-facing NTP are supporting behaviour,
not standalone modules. The status monitor consumes their bounded native
status facts in the existing `DHCP/NTP` and `Tailnet` slots; unconfigured is off,
configured-but-unavailable is failed, and no status database or scheduler is
introduced.

## Capability, provider, runtime

Keep these concepts separate:

| Concept | Meaning | Examples |
| --- | --- | --- |
| Capability | What the operator manages | firewall, DHCP, DNS, VPN, monitoring, status page, printer |
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
