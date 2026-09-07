---
layout: default
title: Focused OpenWrt provider qualification
section: lab
description: Focused follow-up qualification and final OpenWrt provider decision.
---

# Focused OpenWrt provider qualification

## Final decision

**NO-GO** for OpenWrt as Boetticher's initial provider for `firewall`, `dhcp`,
and `dns`.

The prior broad spike proved a useful API-managed IPv4 gateway. This focused
run found substantive remaining gaps, so appliance evaluation stops here. The
next spike should be the bounded Debian/nftables/dnsmasq/Stubby/chrony design;
do not start another appliance search.

The decisive failures are:

1. OpenWrt's native DHCP-derived DNS names remain global
   (`<name>.lab.home.arpa`), not the required managed reservation contract
   (`<name>.<zone>.lab.home.arpa`).
2. The Controller root-only credential store was not qualified, and the scoped
   automation identity could not rotate its own rpcd credential through the
   tested API scope.
3. No AirVPN profile or account control-plane binding was available. The run
   qualified a synthetic WireGuard peer, not AirVPN tunnel establishment,
   provider port allocation, or AirVPN-assigned inbound forwarding.

This is a final focused decision, not a claim that every previously proven
OpenWrt journey failed.

## Scope and provenance

| Item | Value |
| --- | --- |
| Branch | `module/openwrt-focused-spike` |
| Starting SHA | `d01f5c49b8c75a5b602f8e4c8e0915e35fa482c9` |
| Prior broad report | `docs/networking/openwrt-provider.md` at the starting SHA |
| Host | `lab-proxmox-01`, `192.168.4.5` |
| Proxmox | `9.2.2` |
| Disposable VM | VMID `982`, `boetticher-openwrt-focused-spike` |
| VM NICs | `52:54:00:98:30:01` on `vmbr0`; `52:54:00:98:30:02` on `vmbr1` |
| Storage | `boetticher-data`, imported 124 MiB boot disk |
| OpenWrt | `25.12.5` x86/64 generic ext4 combined |
| ImageBuilder revision | `r33051-f5dae5ece4` |
| Focused image SHA-256 | `db17427aa9a41f434e2ee32642d7301caacc3d985b6f64f1e54952defb9be943` |
| Run window | 7 September 2026 |

The release and target are from the [official OpenWrt 25.12.5 x86/64 release
index](https://downloads.openwrt.org/releases/25.12.5/targets/x86/64/). The
ImageBuilder ran in a clean Docker `linux/amd64` Ubuntu 24.04 container and
reported `x86_64`. It emitted no prior arm64/fakeroot `LD_PRELOAD` warnings.
It did emit standard ImageBuilder boot-copy and BIOS-partition warnings; the
build nevertheless completed successfully. The package set added only:
`uhttpd`, `uhttpd-mod-ubus`, `rpcd`, `px5g-mbedtls`, `stubby`, `qemu-ga`,
`kmod-wireguard`, `wireguard-tools`, and `ip-full`. LuCI was not installed.

Previous broad evidence was reused for the six VLAN definitions, ordinary NAT,
basic Internet and isolation journeys, static DNS CRUD, basic DoT transport,
and the original native collision observations. Those journeys were not
needlessly repeated.

## Bootstrap and credentials

### Unattended bootstrap: PASS

The qualifying image used official ImageBuilder plus an embedded
`uci-defaults` first-boot script. It automatically created the dedicated
`boetticher` rpcd identity from a generated password hash, configured HOME
management, disabled the unwanted default HOME DHCP/IPv6 paths, enabled HTTPS,
installed the scoped ACL, and enabled QEMU guest agent support.

No console interaction, default-password dependency, GUI automation, SSH
mutation, PHP, or post-boot configuration-file surgery was used.

The generated appliance certificate was pinned locally. The observed SHA-256
fingerprint was
`89:AB:1F:2C:F0:EB:53:DF:FE:1E:F1:65:24:BE:AA:DF:08:55:32:A1:B3:7C:69:03:1C:E1:3D:AF:D4:70:17:30`.
Normal API calls verified the certificate and hostname; no `--insecure` call
was used for normal lifecycle.

### Credential lifecycle: HOLD

| Requirement | Result |
| --- | --- |
| Secret absent from git, report, logs, and normal argv | **PASS** — generated credential remained in memory for the qualification and was removed with the temporary build tree |
| Controller root-only store | **NOT TESTED** — the local harness had no non-interactive root-capable Controller store; no production credential path was claimed |
| Credential survives provider reboot | **PASS** — re-authentication succeeded after clean QEMU guest-agent shutdown/start |
| Credential rotation | **HOLD** — `uci.get` for `rpcd` returned access denied (`6`) under the scoped identity |
| Normal API management | **PASS** — configuration used HTTPS `/ubus` JSON-RPC and UCI |

The normal production credential location remains a design requirement, not a
qualification result. Broadening the ACL to allow self-rotation would be an
explicit privilege compromise requiring a new review.

The supported API surface used here is described by the [OpenWrt UCI ubus
API](https://openwrt.org/docs/guide-developer/ubus/uci), [ubus session
API](https://openwrt.org/docs/guide-developer/ubus/session), and [secure access
guidance](https://openwrt.org/docs/guide-user/security/secure.access).

## Managed naming decision

The required product contract remains:

```text
managed reservation:
    <name>.<zone>.lab.home.arpa
```

OpenWrt did not provide it through native DHCP/dnsmasq integration. After a
real DHCP renewal, the observed results were:

| Query | Result |
| --- | --- |
| `managed-trusted.lab.home.arpa A` | `10.10.30.50` |
| `managed-trusted.trusted.lab.home.arpa A` | Empty |
| `10.10.30.50 PTR` | `managed-trusted.lab.home.arpa.` |

Per-interface `domain` values did not create per-zone DNS suffixes. The
fallback `<name>.lab.home.arpa` contract is explicit and understood, but it is
not accepted for this provider decision because the missing zone qualification
applies to managed reservations, not merely transient unknown clients.

No custom DDNS synchronizer, RFC2136/TSIG path, or second DNS inventory was
introduced.

## Reservation prevalidation decision

### Simple validation: PASS as a bounded design

A disposable validator rejected a desired-state input containing duplicate IP,
duplicate MAC, and duplicate managed FQDN values before making any provider
call. Native DHCP section count remained `9` before and after, proving no
provider mutation. This is straightforward input validation, not a shadow
inventory or database.

### Native collision behavior: still disqualifying

The broad spike's live observations remain authoritative:

| Collision | Native behavior |
| --- | --- |
| Duplicate reserved IP | dnsmasq crashed and entered a restart loop |
| Duplicate MAC | Accepted with later-entry-wins behavior |
| Duplicate hostname | Leases were issued, but forward/reverse DNS was lossy |

Simple prevalidation can make those inputs unreachable if it is implemented at
the desired-state boundary. It does not repair native provider behavior or
qualify a production adapter by itself.

## WireGuard and AirVPN-focused results

No AirVPN credential/profile or AirVPN port-allocation API binding was supplied
to this qualification. Therefore the
following results are explicitly **synthetic WireGuard qualification**, not
AirVPN qualification.

### Synthetic WireGuard: PASS for bounded routing semantics

The provider was configured through UCI/API with:

* a WireGuard interface and peer;
* source-based `10.10.30.0/24` policy routing to table `51820`;
* connected routes for the selected source and tunnel networks;
* an `airvpn` firewall zone with masquerading;
* selected TRUSTED forwarding only; and
* TCP and UDP redirects to a temporary SERVERS listener.

The run found and corrected two real lifecycle details through supported API
operations: the policy table needed connected routes, and the scoped ACL did
not allow `network.restart`; the already-scoped service lifecycle operation was
used to restart network state. No direct `wg` mutation was used on OpenWrt.

| Journey | Result |
| --- | --- |
| Selected TRUSTED TCP egress to `1.1.1.1:443` | **PASS** — connection succeeded and peer transfer counters increased |
| Peer-loss killswitch | **PASS** — removing the synthetic peer made selected egress fail with no HOME fallback |
| HOME management transport during peer loss | **PASS** — HTTPS transport remained reachable over the Host path |
| TCP inbound redirect `40000 -> 10.10.20.50:8080` | **PASS** |
| UDP inbound redirect `40001 -> 10.10.20.50:8081` | **PASS** |
| Reapply | **PASS** — active peer and forwarding objects did not duplicate |
| Actual AirVPN tunnel | **NOT TESTED** |
| AirVPN provider port allocation/control plane | **NOT TESTED** |
| AirVPN-assigned TCP/UDP forwarding | **NOT TESTED** |

A synthetic peer is sufficient to test UCI routing and fail-closed semantics,
but it cannot establish the required AirVPN provider decision. A successful
tunnel alone would not have been enough for a GO.

## Reapply and failure behavior

The same desired values were applied again through the API without byte-for-byte
config comparison. Native section counts were stable:

```text
network  24 -> 24
dhcp      9 -> 9
firewall 20 -> 20
```

The active WireGuard peer retained the intended `0.0.0.0/0` cryptokey range,
and each TCP/UDP forwarding remained one UCI redirect section. The identity was
not regenerated. Harmless service restarts required by the supported service
boundary were recorded; no duplicate policy was created.

Failure evidence:

* invalid reservation input was rejected before provider mutation;
* removing the tunnel peer failed closed without breaking HOME management;
* a clean provider restart restored valid network, DHCP, firewall, and
  WireGuard state; and
* a failed attempt to call the unscoped `network.restart` method returned access
  denied without changing valid provider state.

No rollback journal, mutation ledger, transaction database, or persistent test
state was added.

## Clean reboot and teardown

QEMU guest agent was present and responsive. The provider shut down cleanly
through `qm shutdown`, restarted, and answered `qm agent 982 ping`. Post-reboot
API re-authentication passed and native counts remained `network=24`, `dhcp=9`,
and `firewall=20`.

Final cleanup removed the exact disposable VM, disk, namespaces, temporary veths,
DHCP lease material, build tree, trust certificate, and credential material.
Final Host readback showed:

* VMID 982 absent; QEMU and LXC guest inventories empty;
* `boetticher-data` healthy and at 0% used;
* `vmbr0` still carrying `192.168.4.5/22`;
* `vmbr1` still virtual-only, VLAN-aware, and without an address;
* no temporary namespace or veth residue; and
* Host identity still `lab-proxmox-01`.

The physical LAB NIC, external switch, physical trunk, HOME management,
Controller trust, and unrelated provider state were not modified.

## Intentionally not tested

The focused run does not claim evidence for:

* an actual AirVPN account/tunnel or provider port reservation;
* Controller root-only persistent credential storage and teardown;
* credential rotation under a production-approved ACL;
* OpenWrt Unbound itself; the prior run used dnsmasq plus stubby;
* IPv6, HA, firmware lifecycle, DoH blocking, or generic policy DSL behavior;
* production Module implementation; or
* any physical LAB networking.

## Repository verification

The only intended repository change is this focused report. The required
focused checks passed:

| Check | Result |
| --- | --- |
| `git diff --check` | **PASS** |
| `go test ./internal/naming` | **PASS** |
| `go test ./internal/contract -run TestDocsSiteKeepsOneSmallGuideSet` | **PASS** |
| `make ci` | **FAIL / pre-existing** — `TestReleaseWorkflowHasNonPublishingManualRehearsal` cannot open the absent `.github/workflows/release.yml`; the remaining package tests completed successfully |

The obsolete release workflow was not restored merely to make this focused
branch green.
