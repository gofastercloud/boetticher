---
layout: default
title: OpenWrt provider qualification
section: lab
description: Disposable OpenWrt provider qualification spike and decision record.
---

# OpenWrt provider qualification spike

Status: **CONDITIONAL GO for a narrowed IPv4 provider; NO-GO for the current
Boetticher DHCP/DNS contract.** Production Module implementation remains
**HOLD**.

This was a disposable qualification spike, not a production provider or Module
implementation. The run evaluated whether OpenWrt can be provisioned and
managed unattended through supported APIs and ordinary Proxmox VM lifecycle
operations.

## Decision

OpenWrt is technically viable as an automation-first provider for the bounded
IPv4 firewall, routing, basic DHCP, local DNS, encrypted upstream DNS, and NTP
plumbing tested here. The first-boot API bootstrap can be embedded in an
ImageBuilder-produced image; normal configuration can then use the supported
`/ubus` JSON-RPC API over verified HTTPS.

It is **not qualified for the current desired Boetticher contract** because the
native DHCP/DNS integration does not produce the required per-zone names and
has unsafe collision behavior:

* DHCP-derived names were published below `lab.home.arpa`, not below the
  requested zone-specific suffixes such as
  `dynamic-trusted.trusted.lab.home.arpa`.
* A duplicate reserved IP caused dnsmasq to enter a crash/restart loop.
* A duplicate MAC was accepted with last-entry-wins behavior.
* Duplicate hostnames were accepted, but forward and reverse DNS represented
  only part of the resulting lease set.

The practical recommendation is therefore:

| Decision | Scope |
| --- | --- |
| **CONDITIONAL GO** | A narrowed provider contract accepting OpenWrt-native DHCP/DNS naming and rejecting or pre-validating conflicting reservations before apply. |
| **NO-GO** | The current requirement for zone-specific DHCP-derived names and safe native collision semantics. |
| **HOLD** | `module firewall`, `module dhcp`, and `module dns` production implementation until the contract is explicitly narrowed or the failed behaviors are solved without appliance file mutation. |

## Run and boundary

| Item | Value |
| --- | --- |
| Branch | `module/openwrt-spike` |
| Starting revision | `a2ebcfae` |
| Host | `lab-proxmox-01` at `192.168.4.5` |
| Proxmox | `9.2.2` |
| Disposable VM | VMID `982`, `boetticher-openwrt-spike` |
| VM shape | 2 vCPU, 4 GiB RAM, 124 MiB imported boot disk on `boetticher-data` |
| NICs | HOME on `vmbr0`; LAB trunk on existing virtual-only `vmbr1` |
| Provider image | OpenWrt `25.12.5`, x86/64 generic ext4 combined |
| Qualification image SHA-256 | `f28178a6173d245e32e29b5b184713094f95c2b3a079a80002b822be8242e71d` |
| Run window | 6–7 September 2026 |

The selected release and target image are recorded in the [OpenWrt 25.12.5
x86/64 release index](https://downloads.openwrt.org/releases/25.12.5/targets/x86/64/).
The official compressed base-image SHA-256 was
`23e2538e8ab0eb52dfed1c65d608ecdb71ffd432dd54885da138ae67cd9e4461`.

No physical LAB NIC, external switch, physical trunk, HOME management, Host
storage layout, or existing Controller trust was changed.

## Automation and bootstrap

### Result: PASS for unattended bootstrap

The qualifying image was built with the official OpenWrt ImageBuilder. The
image included `uhttpd`, `uhttpd-mod-ubus`, `rpcd`, `px5g-mbedtls`, `stubby`, a
`uci-defaults` first-boot script, an rpcd ACL, and a seeded rpcd configuration.

The first-boot script automatically:

1. created the dedicated `boetticher` rpcd identity with a generated password
   hash;
2. assigned the HOME management address `192.168.4.28/22`;
3. disabled provider-side IPv6 and the default HOME DHCP server;
4. configured HTTP-to-HTTPS redirection and the generated appliance
   certificate; and
5. restarted the required services.

The first image was intentionally tested with a manual serial bootstrap and
discarded as disqualifying evidence. The final qualification used the
ImageBuilder image and required no console clicks, manual edits, SSH mutation,
PHP, or configuration-file surgery.

The ImageBuilder build emitted repeated `LD_PRELOAD` warnings from its
fakeroot tooling because the build ran in a disposable arm64 build container
for an x86/64 target. The build still completed and the image booted, but this
is an operational compromise: a production build path must use a reproducible
builder environment whose architecture and fakeroot layout are qualified.

### API authentication and TLS

| Gate | Result | Evidence |
| --- | --- | --- |
| Dedicated automation identity | **PASS** | `boetticher` authenticated through rpcd over HTTPS. |
| Normal lifecycle uses API | **PASS** | Network, firewall, DHCP, DNS, stubby, and NTP changes were made through ubus/UCI API calls. |
| Secret in argv/logs/committed files | **PASS** | The temporary password was generated and retained in memory by the qualification harness; it was not written to a plaintext file or report. |
| Controller root-only persistence | **NOT TESTED / HOLD** | The spike harness did not implement the production Controller credential store. `/var/lib/boetticher/controller/providers/...` remains a production recommendation. |
| Credential persistence over reboot | **PASS** | Re-authentication succeeded after the provider VM was stopped and started. |
| Credential rotation | **NOT TESTED / HOLD** | The scoped automation ACL did not expose the rpcd login package, so the identity could not rotate its own credential through the tested scope. |
| TLS verification | **PASS** | The generated appliance certificate was pinned locally and API calls used certificate and hostname verification; normal calls did not use `--insecure`. |
| Application PKI | **NOT REQUIRED** | A generated appliance certificate plus a Controller-local trust anchor was sufficient for the spike. |

The API path was HTTPS JSON-RPC at `/ubus`, reached through a temporary
Controller-to-Host SSH local forward because the Controller did not directly
route to the disposable HOME address. SSH was used only as transport; it did
not mutate OpenWrt configuration. The exact Host key was verified using the
existing known-host identity.

The supported API model is documented by OpenWrt's [UCI ubus
API](https://openwrt.org/docs/guide-developer/ubus/uci), [ubus session
API](https://openwrt.org/docs/guide-developer/ubus/session), and [secure access
guidance](https://openwrt.org/docs/guide-user/security/secure.access).

## API inventory

The spike proved representative calls before using bounded helper logic. No
generic provider framework or broad API abstraction was introduced.

| Concern | Endpoint / method | Identifier and readback | Apply/reload | Ownership finding |
| --- | --- | --- | --- | --- |
| Authentication | `/ubus`, `session.login` | Session token; sessions are in-memory and recreated after reboot | None | User/login configuration is rpcd/UCI state; not exposed for rotation in the scoped ACL |
| UCI configuration | `/ubus`, `uci.get`, `uci.set`, `uci.add`, `uci.delete`, `uci.commit`, `uci.apply`, `uci.reload_config` | Package plus named section; no provider UUID | `commit` plus `apply` or `reload_config` as appropriate | UCI has no first-class Boetticher ownership field |
| Interfaces/VLANs | UCI `network`; `network.interface dump` | Stable section names and device names such as `vlan5` / `eth1.5` | Network reload | Stable names are usable; ownership is convention-based |
| Firewall/routing/NAT | UCI `firewall` and `network` | Named zone, forwarding, rule, and redirect sections | Firewall reload | Rule `name` is a usable semantic marker, but not a protected ownership namespace |
| DHCP/local DNS | UCI `dhcp`; dnsmasq host records and CNAME records | Named DHCP sections and host sections | dnsmasq reload through service/UCI apply | Native host sections are addressable; collision checks are weak |
| Encrypted upstream DNS | UCI `stubby`; generated stubby configuration | Named global/resolver sections | stubby reload/restart | Resolver names and fields are addressable; no generic resolver abstraction needed |
| NTP | UCI `system.ntp`; service state | Named server list and `enable_server` | NTP service reload | Standard UCI state; not a public Module |
| Diagnostics | `network.interface dump`, UCI reads, service/status queries, packet capture | Native interface, route, lease, and service state | Read-only | Native provider state was sufficient for this spike |
| WireGuard | UCI `network`/`firewall` | Not exercised | Not exercised | **NOT TESTED**; optional AirVPN path remains unqualified |

The [OpenWrt rpcd UCI implementation](https://git.openwrt.org/project/rpcd/tree/uci.c)
supports the tested UCI object operations. This is sufficient for the bounded
configuration surface, but the absence of a first-class ownership field means
production reconciliation would have to use stable Boetticher semantic names
and preserve all unrelated sections.

## Network and IPv4 provider configuration

### Result: PASS

The provider's HOME interface was `br-lan`/`eth0`, and the LAB interface was
`eth1`. The API created and assigned the six VLAN interfaces and configured the
following IPv4 gateways:

| VLAN | Zone | Device | Gateway |
| ---: | --- | --- | --- |
| 5 | TRANSIT | `eth1.5` | `10.10.5.1/24` |
| 10 | INFRA | `eth1.10` | `10.10.10.1/24` |
| 20 | SERVERS | `eth1.20` | `10.10.20.1/24` |
| 30 | TRUSTED | `eth1.30` | `10.10.30.1/24` |
| 40 | SANDBOX | `eth1.40` | `10.10.40.1/24` |
| 99 | MGMT | `eth1.99` | `10.10.99.1/24` |

The provider had no usable IPv6 addresses or IPv6 forwarding configuration.
The HOME DHCP server, IPv6 delegation, DHCPv6, and router advertisements were
disabled. IPv6 was not otherwise qualified.

The reapply test rewrote the same named sections through the API. Counts stayed
stable (`network=12`, including VLAN devices and interfaces), with no duplicate
interfaces or gateways.

The existing Host-owned `vmbr1` was inspected and used as the virtual LAB
trunk. It remained the Host responsibility. The spike does not justify moving
bridge ownership into a future firewall provider apply, and no such migration
was performed.

## DHCP

### Result: PARTIAL PASS

The six networks were configured through UCI/dnsmasq API calls. TRANSIT, INFRA,
and MGMT were reservation-only; SERVERS, TRUSTED, and SANDBOX had dynamic pools.
All zones received gateway, DNS, NTP, lease-time, and local-domain options as
appropriate. The [OpenWrt DHCP/DNS configuration
guide](https://openwrt.org/docs/guide-user/base-system/dhcp) documents the
native dnsmasq model used here.

Live DHCP results:

| Journey | Result |
| --- | --- |
| Unknown INFRA client | **PASS** — no offer and no lease |
| Reserved INFRA client | **PASS** — `10.10.10.50`, later moved to `.51` |
| Reserved SERVERS client | **PASS** — `10.10.20.50` |
| Dynamic TRUSTED client | **PASS** — `10.10.30.103` |
| Dynamic SANDBOX client | **PASS** — `10.10.40.133` |
| DHCP option 3 | **PASS** — zone gateway advertised |
| DHCP option 6 | **PASS** — provider advertised as DNS server |
| DHCP option 42 | **PASS** — provider advertised as NTP server |
| Repeat apply | **PASS** — no duplicate ranges or reservations |

The first static-only configuration used zero-length ranges and caused dnsmasq
startup errors. Removing the range fields and retaining `dynamicdhcp=0` fixed
the configuration through the API. This is a provider-specific implementation
detail that must be encoded in any future bounded adapter.

## Local DNS and DHCP-derived names

### Result: NO-GO for the requested namespace; PARTIAL PASS for native behavior

The local namespace was `lab.home.arpa`, with intended zone names for TRANSIT,
INFRA, SERVERS, TRUSTED, SANDBOX, and MGMT. The provider correctly returned
reservation-based A and PTR records and supported static A and CNAME records.

The required per-zone DHCP-derived names did not materialize. The observed
records were:

| Query | Observed result |
| --- | --- |
| `dynamic-trusted.lab.home.arpa A` | `10.10.30.103` |
| `dynamic-sandbox.lab.home.arpa A` | `10.10.40.133` |
| `dynamic-trusted.trusted.lab.home.arpa A` | Empty |
| `dynamic-sandbox.sandbox.lab.home.arpa A` | Empty |
| `103.30.10.10.in-addr.arpa PTR` | `dynamic-trusted.lab.home.arpa.` |
| `133.40.10.10.in-addr.arpa PTR` | `dynamic-sandbox.lab.home.arpa.` |

Reservation changes did update both forward and reverse state: moving the
INFRA reservation from `.50` to `.51` removed the old A/PTR result and produced
`test-infra.lab.home.arpa` at `.51`.

Static DNS lifecycle was API-manageable:

* an A record was created and updated from `.60` to `.61`;
* a CNAME pointed at the A record and resolved correctly;
* both records were deleted by exact owned section name; and
* an unrelated simulated operator record remained untouched.

This supports a future bounded `module dns add-record` shape, subject to the
ownership and collision restrictions below. No RFC2136, TSIG, PowerDNS, or
custom DDNS script was needed.

## Collision semantics

These results are material product evidence, not merely documentation gaps.

| Collision | Provider behavior | Decision impact |
| --- | --- | --- |
| Duplicate reserved IP | dnsmasq reported `duplicate dhcp-host IP address`, failed to start, and entered a crash/restart loop | **FAIL** for safe apply behavior; pre-validation would be mandatory |
| Duplicate MAC with different IP | Accepted; the later reservation won and the client received the later IP | **HOLD**; deterministic but unsafe and surprising |
| Duplicate hostname | Two leases were issued, but A lookup returned only one address and only one corresponding PTR was visible | **HOLD**; lossy native DNS behavior |

The exact temporary collision sections were removed through the API and dnsmasq
recovered. No collision database was added to Boetticher.

## Upstream DNS

### Result: PARTIAL PASS; HOLD for the explicit Unbound and DNSSEC requirements

This run used native dnsmasq forwarding to a local stubby listener on
`127.0.0.1:5453`, with Quad9 resolvers `9.9.9.9` and `149.112.112.112` over
DNS-over-TLS on TCP port 853 and TLS name `dns.quad9.net`.

The Unbound package was not installed or qualified, so the explicit Unbound
requirement is **NOT TESTED**. The encrypted-forwarding result below is a
successful alternative transport test, not evidence that an Unbound provider
implementation is complete.

The test initially exposed two provider details: stubby needed a timed trigger
because no `wan` interface existed, and the transport needed the list-valued
`GETDNS_TRANSPORT_TLS` setting. Both were corrected using supported API/UCI
operations.

Evidence:

* external lookups succeeded;
* a packet capture showed TCP/853 to Quad9 and no outbound port-53 dependency;
* a valid DNSSEC domain resolved; and
* `dnssec-failed.org` returned `SERVFAIL`.

Stubby nevertheless reported that DNSSEC validation was off in this setup, so
the last result cannot be credited as locally enforced DNSSEC validation.
Local `lab.home.arpa` records continued to resolve independently of upstream
filtering. No DoH blocking was attempted.

## Firewall, forwarding, and NAT

### Result: PASS for the tested bounded IPv4 journeys

The API configured named zones and forwardings, retained masquerading on the
HOME path, and added semantic rules for:

* `boetticher-sandbox-private-deny`; and
* `boetticher-sandbox-direct-dns`.

Packet journeys passed:

| Journey | Result |
| --- | --- |
| TRUSTED to Internet HTTPS | **PASS** — HTTP 200 |
| SANDBOX to Internet HTTPS | **PASS** — HTTP 200 |
| SANDBOX direct DNS to `1.1.1.1` | **PASS** — blocked |
| SANDBOX to private TRUSTED address | **PASS** — blocked |

Selective ownership also passed. The two named Boetticher rules were deleted
through the API while an unrelated simulated operator rule remained present.
No generic firewall policy DSL or second inventory database was introduced.

## Time service

### Result: PARTIAL PASS

The native NTP service was configured with multiple OpenWrt pool sources and
enabled as a provider-side server. UDP/123 was reachable from a TRUSTED client,
and DHCP option 42 advertised the provider address.

Client synchronization against the provider was not independently exercised,
so full client time synchronization is **NOT TESTED**.

## Reboot, persistence, and teardown

### Result: PASS with a lifecycle compromise

The VM was stopped and started using normal Proxmox lifecycle operations. A
graceful guest shutdown was unavailable because QEMU guest agent was not
installed, so the test used the documented fallback stop/start path. After
boot:

* the `boetticher` identity re-authenticated over verified HTTPS;
* network, DHCP, stubby, and firewall UCI state remained present;
* the post-reboot readback was `network=12 dhcp=9 stubby=3 firewall=9`; and
* API configuration did not duplicate.

The absence of QEMU guest agent is an operational compromise for production
VM lifecycle and should be resolved or explicitly accepted before deployment.

The exact owned temporary firewall and DNS sections were removed through the
API. VMID 982 and its disk were then removed. Final Host readback showed:

* VMID 982 absent and the guest inventory empty;
* `boetticher-data` at 0% used after cleanup;
* `vmbr0` still carrying `192.168.4.5/22`;
* `vmbr1` still virtual-only, VLAN-aware, and without an IPv4/IPv6 address;
* no temporary test veths or bridge ports; and
* Host runtime identity restored and verified as `lab-proxmox-01`.

One test-harness mistake changed the Host runtime hostname while attempting to
set a namespace hostname. It was immediately restored before final provider
operations, and the final Proxmox node and bridge readback above passed. This
was a harness defect, not a provider feature or an accepted production
procedure.

## Production architecture if the conditions are accepted

The narrowest viable architecture is:

```text
Controller
    |
    | HTTPS JSON-RPC /ubus
    v
OpenWrt provider VM
    +-- eth0 -> HOME / vmbr0
    +-- eth1 -> Host-owned virtual LAB trunk / vmbr1
          +-- VLAN 5   TRANSIT  10.10.5.1/24
          +-- VLAN 10  INFRA    10.10.10.1/24
          +-- VLAN 20  SERVERS  10.10.20.1/24
          +-- VLAN 30  TRUSTED  10.10.30.1/24
          +-- VLAN 40  SANDBOX  10.10.40.1/24
          +-- VLAN 99  MGMT     10.10.99.1/24
```

The Host should continue to own `vmbr1`. The provider should inspect and
require the bridge, while refusing conflicting state. The public Boetticher
capabilities remain `module firewall`, `module dhcp`, and `module dns`; the
OpenWrt provider is not a public Module and NTP remains provider plumbing.

Before production implementation, the following conditions must be resolved:

1. decide whether the product accepts OpenWrt-native global DHCP-derived names
   or requires a different supported provider/DNS model;
2. add deterministic preflight rejection for duplicate IP, MAC, and hostname
   inputs without relying on an untrusted second inventory;
3. qualify Controller root-only credential storage and a supported rotation
   procedure, or explicitly widen the bounded rpcd ACL;
4. qualify a reproducible ImageBuilder build environment without the fakeroot
   warnings; and
5. decide whether QEMU guest agent support is required for graceful provider
   reboot.

AirVPN/WireGuard, port forwarding, and killswitch behavior were not tested and
remain outside this decision.

## Repository verification

The report is the only intended repository change from this spike.

| Check | Result |
| --- | --- |
| `go test ./internal/naming` | **PASS** |
| `go test ./internal/contract -run TestDocsSiteKeepsOneSmallGuideSet` | **PASS** |
| `git diff --check` | **PASS** |
| `make ci` | **FAIL / pre-existing** — `TestReleaseWorkflowHasNonPublishingManualRehearsal` cannot open the absent `.github/workflows/release.yml`; the remaining package tests completed successfully. |

The release-gate failure is unchanged and was not masked or repaired as part
of this spike.
