---
layout: default
title: Firewall capability
section: lab
description: Phase 4A firewall capability contract and boundaries.
---

# Firewall capability — Phase 4A

Phase 4A delivers the first production Module capability:

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

The operator manages a firewall capability. OpenWrt 25.12.5 x86/64, built by
the pinned official ImageBuilder revision `r33051-f5dae5ece4`, is the current
provider implementation. Provider-specific nouns are intentionally absent
from the normal command grammar.

## Ownership

The capability owns the exact provider identity `lab-firewall-01` (VMID 280 in
the current allocation scheme), its provider disk and two virtual NICs, the
provider image cache, Controller-local provider credential and pinned TLS
trust, six LAB IPv4 gateways, firewall policy, and ordinary Internet NAT.

The Host owns Proxmox, `boetticher-data`, `vmbr0`, `vmbr1`, Host trust, and
physical networking. Firewall apply verifies that `vmbr1` is present, VLAN
aware, virtual-only, and compatible; it fails with an instruction to run or
fix `host apply` instead of repairing Host state.

The HOME management binding is explicit site intent at
`gateway.management_address`, `gateway.management_network`, and
`gateway.management_gateway`; `gateway.controller_address` is the only HOME
source allowed to reach provider administration. Older site files receive the
reference defaults `192.168.4.28/22` via `192.168.4.1`, with Controller
`192.168.4.6`. The provider uses this HOME interface for its default route and
NAT; it does not alter HOME routing or DHCP.

## Network and policy

The provider receives one HOME NIC on `vmbr0` and one untagged LAB trunk NIC
on `vmbr1`. It creates gateway interfaces at `.1` for VLANs 5, 10, 20, 30, 40,
and 99. The capability is IPv4-only. Provider-side DHCP and DNS are disabled
in Phase 4A.

The Proxmox Host management address is `10.10.99.5/32` on MGMT. The firewall
allows only TCP/22 to that exact address from TRUSTED `10.10.30.0/24` and the
Tailnet router `10.10.5.10/32`; all other MGMT access remains denied by default.

The fixed reference policy is default-deny for provider input and unspecified
inter-zone forwarding. TRUSTED, SERVERS, INFRA, SANDBOX, and MGMT may use
ordinary HOME/WAN NAT; TRANSIT may not. TRUSTED may initiate toward SERVERS,
SERVERS/INFRA cannot initiate toward TRUSTED, SANDBOX cannot initiate toward
other LAB zones, and MGMT has broad reference-lab access to other LAB zones.
Provider management is permitted only from the HOME management path; LAB
clients do not receive access to `/ubus`.

## Lifecycle safety

`plan` is read-only and reports meaningful provider/network/policy categories.
`apply` reconciles only deterministic named provider sections and preserves
unrelated provider-native sections. It reuses the provider credential,
certificate, image cache, VM, and correct UCI state. `status` is a cheap
operational view, not qualification evidence; it verifies provider
identity/running state, authenticated API reachability, six gateway interfaces,
active firewall runtime, and an IPv4 HOME default route. `teardown` requires
explicit approval and removes only the exact owned provider identity and
Controller state. A failed first apply leaves understandable provider state
for the next apply to inspect and continue.

This source implementation is not live qualification evidence. The required
packet journeys, provider reboot, teardown/rebuild rehearsal, and final
clean-install gate remain **NOT TESTED** until run against the enrolled
reference Host. Local tests prove deterministic generation and ownership
boundaries only.

## Phase 4A closeout state

The final enrolled-lab closeout run established fresh apply, semantic no-op,
provider reboot/recovery, independent routed-IPv4 packet acceptance, bounded
interruption cleanup, teardown, and preservation of the Controller and Host.
The run ended with no firewall deployed; absent status is expected and returns
nonzero, while the plan proposes creation again. The readiness repair retains
the last management failure and waits for authenticated HTTPS/ubus readiness;
the cleanup repair keeps lock ownership in the internal cleanup path and gives
cancellation a fresh cleanup budget.

Physical Blinkt/StreamDeck navigation, refresh, and unplug/replug checks were
not executable through the available remote session. They remain **NOT
TESTED**, so physical-peripheral acceptance is separate from the passing
software and routed-packet gates.

## Packet acceptance

The supported packet command is:

```text
boetticher module firewall test [--yes|--plan|--cleanup-only --yes]
```

It runs only against an already-deployed firewall. The Host helper creates six
temporary network namespaces (`bt4a-transit`, `bt4a-infra`,
`bt4a-servers`, `bt4a-trusted`, `bt4a-sandbox`, and `bt4a-mgmt`), one veth
pair per namespace, and one new vmbr1 access port with the authoritative zone
VLAN. Each fixture receives a static address selected from `.250-.254` after a
bounded duplicate-address check and routes through its firewall gateway.
Existing guests, ports, VLAN globals, physical interfaces, Host routes, and
provider policy are not changed. No DHCP, DNS, NTP, VPN, physical trunking,
packet capture, nmap scan, iperf benchmark, signed probe artifact, application
PKI, or persisted evidence report is involved.

The fixed expectations cover all six gateway checks; HTTPS egress from INFRA,
SERVERS, TRUSTED, SANDBOX, and MGMT with TRANSIT denied; the stated TCP and UDP
inter-zone controls; LAB-to-HOME protection; Controller-only HTTPS API access;
LAB administration denial at the provider HOME and gateway addresses; and one
credential-free Host HOME attempt. A positive listener/control is established
before a prohibited path is interpreted as a deny. Setup, transport, missing
listeners, malformed output, TLS failure, and unavailable endpoints are
failures or unproven results, never successful blocks.

`test --plan` creates nothing. A normal run always attempts bounded cleanup
with a fresh cleanup context, including after interruption. Failed cleanup is a
failed test; `test --cleanup-only --yes` is the supported recovery and refuses
ambiguous ownership. This suite validates routed IPv4 policy only; it does not
claim same-VLAN, physical-switch, Wi-Fi, guest-firewall, or IPv6 isolation.

The existing Controller status monitor represents the firewall check on the
`FW` Blinkt slot and the StreamDeck Host-detail view. Phase 4B adds peer
`module dns` and `module dhcp` operations on this same appliance; DHCP-derived
DNS and client-facing NTP are supporting functions, not standalone modules.
Their status facts use the same polling/debounce model without a status
database or repair loop. Physical trunking and external switching remain out
of scope.
