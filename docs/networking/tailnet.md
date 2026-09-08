---
layout: default
title: Tailnet
section: networking
description: The fixed Tailnet subnet-router contract.
---

# Tailnet subnet router

`boetticher module tailnet` manages one unprivileged LXC, `lab-tailnet-01`
(VMID 200), on `vmbr1` VLAN 5. Its exact TRANSIT address is `10.10.5.10`
with MAC `02:00:00:00:05:10`; it advertises `10.10.0.0/16` and applies SNAT.

Apply reads an auth key only after confirmation, from the operator supplied
`--auth-key-file`. The file must be a private regular non-symlink and is
bounded to 16 KiB. The key is streamed to the guest for enrollment and is not
stored in `lab.yml`, the Controller package, or logs. Existing enrollment is
reused; a supplied key is ignored unless native status requires enrollment.

The guest policy is fail-closed. It permits only the reference SERVERS and
TRUSTED routed destinations and gateway DNS/NTP, while denying HOME, INFRA,
MGMT, SANDBOX, TRANSIT neighbors, unallocated ranges, Internet destinations,
and IPv6. Native status verifies the loaded policy, TUN, exact preferences,
route approval, package version, and persistent runtime files.

This status is local evidence. It does not prove remote peer reachability,
manual split-DNS grants, packet journeys through the physical network, or
same-VLAN/Wi-Fi isolation. The bounded module test reports those acceptance
dimensions separately as `NOT TESTED`. Key expiry and machine approval are
recovery conditions handled by a subsequent approved apply. Phase 4D is a
rebase point for 4E integration and recovery, not a qualified rollout.
