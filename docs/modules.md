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
boetticher module statuspage status
boetticher module printer status
```

DHCP-derived DNS and client-facing NTP are supporting behaviour of the peer
`dhcp` and `dns` capabilities, not standalone capabilities. VPN dispatch,
provider reconciliation, fail-closed policy, and Controller-daemon observation
are implemented; remote and physical acceptance remain separate gates. VPN
provider reboot and teardown inspect the enrolled Host's complete VM inventory
and each running guest NIC before stopping protection; malformed or unavailable
inventory refuses the mutation, while stopped guests do not block it. This is
source and local-runtime behavior; it does not claim deployment or packet
acceptance.

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

## Arrstack application capability

The application lifecycle uses one fixed amd64 QEMU VM, `lab-arrstack-01`
(VMID 290, `10.10.20.230`, SERVERS VLAN 20), with a 32 GiB root disk and a
configurable persistent media disk on `boetticher-data`. The supported operator
journey is:

```text
boetticher module arrstack plan --plan
boetticher module arrstack apply --cloudflare-token-file /secure/path/token --yes
boetticher module arrstack status
boetticher module arrstack test --yes
boetticher module arrstack teardown --plan
boetticher module arrstack teardown --yes
```

The token path must be an operator-owned private regular file. It is staged only
through the authenticated Host and guest agent, then removed; it is not printed,
stored in intent, or included in status. The peer port comes from the existing
`modules.vpn.forwards` entry `arrstack-qbittorrent` and preserves its TCP/UDP
number. Applying requires the current protected-service state and a healthy VPN
handshake before the VM or application starts. A complete protected-guest
inventory is required before provider reboot, VPN teardown, or application
teardown can stop protection; stopped guests are explicitly ignored. These
checks are source and local-runtime safeguards and make no deployment or
packet-acceptance claim.

The VM firewall admits HTTPS only from TRUSTED (`10.10.30.0/24`) and Tailnet
SNAT (`10.10.5.10`); the VPN appliance owns peer-forward provenance. Caddy
rejects unknown service names, Docker forwarding is fail-closed, and IPv6 is
disabled. `status` reports guest application health and VPN health separately.
Local runtime checks are evidence for the installed guest only; remote ingress,
peer packet journeys, physical VLAN isolation, and live public acceptance remain
`NOT TESTED` until executed. Teardown stops the VM and removes aliases and the
peer forward while retaining media, its reservation, and VPN client protection.

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
egress, and identity names; do not add a generic schema. Stage 5 uses the
public Caddy DNS-01 frontend and native journal upload with system trust. The
Host-owned `vmbr1.99` path is `10.10.99.5/24` with LAB routes via `10.10.99.1`.
Stage 5 uses one intentionally integrated `observability` capability. Monitoring,
logging, and status page are query/status facets of that runtime, not separate
deployable Modules. AIOps is a separate optional consumer over observability.

The managed firewall keeps inter-zone forwarding disabled for this access. Its
owned rules allow TCP/22 from TRUSTED and the identity-bound Tailnet router to
MGMT, plus TCP/22 from the resolved Controller SERVERS reservation to the Host
at `10.10.99.5`. After the Host path is applied, re-enroll through the verified
internal address to make it the active Controller connection; the original
HOME address and strict imported SSH trust remain the explicit recovery path.

Defer new network modules, an aggregate coordinator, SSO platforms, and
switch automation. The existing management route remains the boundary.

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

## Phase 5 observability capabilities

The installed Controller owns one atomic observability runtime through the
same single-Host path:

```text
boetticher module observability plan|apply|status|test|teardown|secrets
boetticher module logging query|status
boetticher module monitoring status
boetticher module statuspage status
boetticher module aiops ask QUESTION
boetticher module observability alerts pushover apply|status|test|remove
```

`module observability` creates and reconciles the exact unprivileged
`lab-monitor-01` LXC (VMID 120, VLAN 10) with retained metrics, logs, and
observability state volumes. It owns VictoriaMetrics, VictoriaLogs, Grafana,
Gatus, and the optional explicitly configured Bifrost/Holmes route. Monitoring,
logging, and status page remain read-only facets; they have no independent
lifecycle or runtime ownership. AIOps is an optional consumer over this runtime,
and `module aiops ask` is an explicit model operation.
Teardown stops the whole owned guest and retains its data for a later apply.
Apply provisions the public Caddy frontend and native collection paths. Live
Controller/Host acceptance of that path remains `NOT TESTED` in this phase.
Journal upload uses system trust and no client certificate; metrics use
authenticated HTTPS paths through the fixed internal Caddy address. Ingest
accepts only POST `/upload` from the three resolved collection sources and
does not trust forwarded headers. Metrics paths are fixed per target and use
Basic Auth; arbitrary upstream paths are denied.

When Holmes is enabled under AIOps intent, the same LXC runs the pinned Holmes
0.40 runner on demand. Holmes can use only the local Prometheus-compatible
VictoriaMetrics endpoint and VictoriaLogs endpoint. Bifrost is the sole model
route at `127.0.0.1:4000/v1`; its separate `holmes-client-token` is the only
credential Holmes receives, and upstream provider keys remain Bifrost-only.
`module aiops ask QUESTION` requires normal operator approval before a model
request that may incur charges. The runner is unprivileged and bounded, uses
pinned localhost routes, and does not save transcripts. Kernel-level LXC
egress containment remains `NOT TESTED`.

Pushover is an optional alert contact. `module observability alerts pushover
apply` records the enabled state, title, and priority and may import a bounded
`--credentials-file` containing `user:API`; its credential remains
in the Controller secret store and activation is applied with the atomic
observability lifecycle. `status` never prints keys. `test` accepts a local
`user:API` file, requires approval unless `--yes` is supplied, validates the
account, and sends one clearly labelled normal-priority message without retry.
Disabled or unconfigured Pushover remains inert.

For a fresh apply, provide the operator secrets before creating the guest;
the command reports every missing name without starting a partial runtime:

```text
boetticher module observability secrets set grafana-admin-password
boetticher module observability secrets set cloudflare-dns-token
boetticher module observability apply --public-domain davebarton.cc --yes
```

The Gatus status page uses HTTPS without a password prompt inside the existing
network access boundary. Grafana sign-in and private metrics authentication
remain enabled; no status-page password is required for a fresh deployment.

To opt into Holmes/Bifrost, also set `holmes-client-token` and
`openrouter-api-key`, then apply with the explicit provider model:

```text
boetticher module observability secrets set holmes-client-token
boetticher module observability secrets set openrouter-api-key
boetticher module observability apply --public-domain davebarton.cc --holmes-model openai/gpt-4.1-mini --yes
```

Apply creates only an absent exact guest, refuses foreign or mismatched
identity, uploads the installed provider payload, and verifies the active
provider units and local endpoints. Repeating a healthy apply is a no-op.
`--yes` approves mutation, while an interactive affirmative answer is required
otherwise. Source, package, and offline checks are available locally; live
Controller/Host rollout and live acceptance remain `NOT TESTED` in this phase.
Gatus currently checks the shared provider health endpoints; broader lab
outcome checks remain deferred.

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
