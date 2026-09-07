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
boetticher module firewall teardown
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

The existing Controller status monitor now represents the firewall check on
the `FW` Blinkt slot and the StreamDeck Host-detail view. DHCP/DDNS/NTP and DNS
remain explicitly Off/unconfigured until their capabilities are implemented;
they do not require a new scheduler or status store. DHCP is Phase 4B, DNS is
Phase 4C, and physical trunking/external switching remain out of scope.
