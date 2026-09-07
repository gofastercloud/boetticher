---
layout: default
title: OpenWrt AirVPN qualification
section: lab
description: Final real-AirVPN qualification for the OpenWrt provider.
---

# OpenWrt AirVPN qualification

## Final decision

**OPENWRT GO**, with one explicit external prerequisite: AirVPN must provide a
forwarded port through a one-time account operation. OpenWrt can then manage
the local forwarding and fail-closed policy automatically.

The real AirVPN tunnel, selective egress, ordinary-WAN preservation,
killswitch, recovery, reapply, DNS, and provider reboot all passed through the
already-qualified OpenWrt API/UCI design. AirVPN port allocation itself is not
exposed by the account API surface tested here, so no manual port was created
and no end-to-end unsolicited Internet forwarding claim is made.

## Run details

| Item | Value |
| --- | --- |
| Branch | `module/openwrt-airvpn-test` |
| Starting SHA | `f2b78a1cc5772d5619312cc1254ee09fac649475` |
| Host | `lab-proxmox-01`, `192.168.4.5` |
| Disposable VM | VMID `982`, `boetticher-openwrt-airvpn-test` |
| OpenWrt | `25.12.5` x86/64 generic ext4 combined |
| ImageBuilder revision | `r33051-f5dae5ece4` |
| Image SHA-256 | `341867fb3be39aea990b9c60fe795ec570f226e5cbb86d384595486b86066d87` |
| VM NICs | `52:54:00:98:40:01` on `vmbr0`; `52:54:00:98:40:02` on `vmbr1` |
| Storage | `boetticher-data`, 124 MiB imported disk |

The ImageBuilder ran in a clean x86-64 container. The prior arm64/fakeroot
warning was absent. Standard OpenWrt boot-copy and BIOS-partition warnings
remained, but the build completed successfully.

## AirVPN account API

The API key file was used only in memory and never printed, copied to OpenWrt,
logged, committed, or included in this report. The [AirVPN API settings
page](https://airvpn.org/apisettings/) and [configuration
generator](https://airvpn.org/generator/) were the account-control-plane
surfaces used.

| Operation | Result |
| --- | --- |
| List devices | **PASS** — pre-existing `Default` and `boetticher-airvpn` were preserved |
| Create disposable device | **PASS** — `action=add` created a new device |
| Set requested device name | **HOLD** — the API ignored the requested name and returned `New device` |
| Generate WireGuard profile | **PASS** — Europe selection produced a real profile |
| Delete disposable device | **PASS** — deleted by its captured ID; final list returned only the two pre-existing devices |
| Forwarded-port allocation/read API | **NOT AUTOMATABLE** — tested account endpoints returned `error=Unknown service` and device/userinfo responses exposed no port fields |

The generator request for `servers=australia` returned “zero files”. The
supported Europe selection returned:

```text
generator selection: Europe
endpoint host:      europe.vpn.airdns.org
endpoint port:      1637/UDP
tunnel address:     10.158.131.116/32
allowed IPs:        0.0.0.0/0
```

The runtime endpoint resolved to AirVPN addresses in the `213.152.*.*` range.
The account `userinfo` response reported no active session metadata, so that
API response was not used as tunnel proof; the live endpoint, external-IP, and
WireGuard counter evidence were authoritative.

### Credential safety event

The first disposable generated profile was invalidated immediately after a
parser defect stripped Base64 padding and caused netifd to emit sensitive key
material in a diagnostic message. That AirVPN device was deleted and its
profile was not reused. A fresh device/profile was generated, its key lengths
and derived public key were validated before application, and the second
profile supplied the qualification evidence. No secret value is retained here.

## Real WireGuard and OpenWrt application

The corrected real profile was applied through HTTPS `/ubus` JSON-RPC and UCI:

* OpenWrt interface `airvpn` with the assigned `/32` tunnel address;
* AirVPN peer public key and preshared key;
* endpoint host and port from the generator;
* `0.0.0.0/0` peer allowed-IPs with automatic route installation disabled;
* source rule `10.10.30.0/24 -> table 51820`; and
* connected source/tunnel routes plus the existing API-qualified firewall
  zones.

No direct `wg` mutation, OpenWrt SSH mutation, config-file edit, LuCI, custom
hook, or account key on the provider was used.

Evidence after application:

```text
interface: airvpn
endpoint: 213.152.186.18:1637   # later runtime resolutions varied
allowed IPs: 0.0.0.0/0
latest handshake: present
transfer: RX/TX counters increased
```

## Focused journeys

| Journey | Result | Evidence |
| --- | --- | --- |
| Selected TRUSTED egress | **PASS** | External IP `213.152.186.116`, later `213.152.161.48` |
| Ordinary SERVERS egress | **PASS** | External IP `58.178.88.18` |
| Selective routing | **PASS** | Selected and ordinary clients used different exits concurrently |
| Selected-source killswitch | **PASS** | After peer removal through UCI/API, selected `curl` failed with exit 7 |
| No HOME fallback | **PASS** | Selected source did not return `58.178.88.18`; ordinary client remained online |
| Tunnel recovery | **PASS** | Profile re-added through UCI/API; handshake and AirVPN egress returned |
| Reapply | **PASS** | Native counts stayed `network=16`, `dhcp=7`, `firewall=19`; no duplicate peer/rule |
| Provider reboot | **PASS** | Clean QEMU guest-agent shutdown/start; API re-authentication and tunnel returned |
| Existing-flow failure | **NOT TESTED** | New-connection fail-closed property was sufficient for this bounded run |

The selected post-recovery external IP was `213.152.161.48`; after provider
reboot it was `213.152.161.130`. The ordinary client remained at
`58.178.88.18` after recovery and reboot.

## DNS observation

The selected client resolved both:

```text
focus-local.lab.home.arpa -> 10.10.30.50
openwrt.org               -> 64.226.122.113
```

Stubby generated the intended Quad9 TLS configuration for `9.9.9.9` and
`149.112.112.112` on TCP/853. A Host `nic0` capture observed the provider
source `192.168.4.28` connecting to `149.112.112.112:853`; this traffic exited
through ordinary HOME, not through the AirVPN-selected client policy. No
separate VPN DNS architecture was introduced.

## AirVPN port forwarding

The account API paths tested for port state/allocation returned `Unknown
service`; neither the device response nor `userinfo` contained a usable port
inventory. No browser automation, web scraping, or manual port reservation was
used.

Therefore the separate decisions are:

```text
OpenWrt local forwarding capability:          PASS from prior synthetic run
AirVPN account port allocation automation:    NOT AUTOMATABLE through API
Actual Internet -> AirVPN -> OpenWrt -> LAN:  NOT TESTED without a port
```

This is an AirVPN account-control-plane limitation, not an OpenWrt provider
failure. The accepted production compromise is:

```text
one-time AirVPN forwarded-port reservation
    -> store the port as desired configuration
    -> OpenWrt manages the local redirect and killswitch automatically
```

## Clean reboot and teardown

QEMU guest agent was present and responsive. `qm shutdown` completed cleanly;
the VM restarted, `/ubus` authentication returned with TLS verification, the
AirVPN handshake re-established, selected egress returned, and ordinary egress
remained on HOME/WAN.

Cleanup deleted the exact disposable AirVPN device by API, removed VMID 982 and
its disk, removed temporary clients/namespaces/lease files/build material, and
closed the local HTTPS tunnel. Final Host readback showed:

* VMID 982 absent; QEMU and LXC inventories empty;
* `boetticher-data` healthy and at 0% used;
* `vmbr0` still carrying `192.168.4.5/22`;
* `vmbr1` still VLAN-aware, virtual-only, and without an address;
* only the normal `nic0 -> vmbr0` bridge membership; and
* Host identity still `lab-proxmox-01`.

A stale `owsrv982` namespace/veth from an earlier disposable test was found in
the final readback and removed by exact name. The subsequent readback was
clean. Physical LAB networking, HOME management, Controller trust, Host
storage, and unrelated AirVPN account devices were not changed.

## Repository verification

This branch contains only this final report.

| Check | Result |
| --- | --- |
| `git diff --check` | **PASS** |
| `go test ./internal/naming` | **PASS** |
| `go test ./internal/contract -run TestDocsSiteKeepsOneSmallGuideSet` | **PASS** |
| `make ci` | **FAIL / pre-existing** — `TestReleaseWorkflowHasNonPublishingManualRehearsal` cannot open the absent `.github/workflows/release.yml`; the remaining package tests completed successfully |

The retired workflow was not restored merely to make this branch green.
