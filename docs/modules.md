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

Implemented capabilities include:

```text
boetticher module firewall plan
boetticher module firewall status
boetticher module dhcp status
boetticher module dhcp add-reservation
boetticher module dns status
boetticher module dns add-record
boetticher module vpn status
boetticher module vpn add-client
boetticher module tailnet status
boetticher module tailnet apply --auth-key-file /secure/path/key --yes
boetticher module observability status
boetticher module monitoring status
boetticher module logging status
boetticher module statuspage status
boetticher module media status
```

The full flag list for each is in the generated [command reference](commands.html).
DHCP-derived DNS and client-facing NTP are supporting behaviour of the peer
`dhcp` and `dns` capabilities, not standalone capabilities. On a fresh or HOME
recovery path, firewall, DNS, and DHCP accept `--home-recovery`; the order is in
[Start here](start.html#modules).

Capability status feeds the Controller status daemon through ordinary internal
calls; module collection is single-flight off its event loop and bounded. How
the Blinkt and StreamDeck present those facts is described once, in the
[Controller guide](controller.html#status-daemon-and-peripherals).

## Firewall

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
The provider VM is the LAB gateway, so it is created with `onboot` and Proxmox
startup `order=1`: after a Host boot Proxmox starts it before ordered LAB
guests and, in reverse, shuts it down after them. `apply` restores a missing or
different start order on the existing VM; `plan` lists it as a change and
`status` reports the drift without failing health.
`teardown --yes` removes only the exact firewall provider and Controller-local
provider credential/trust, and refuses while DNS or DHCP is enabled.

`module firewall test` exercises the firewall already present with a fixed
routed-IPv4 packet suite; it never applies, repairs, reboots, or tears it
down. Ownership, policy, the packet suite, and its limits are described in
[Firewall capability](networking/firewall-capability.html).

## DNS and DHCP

`module dns` and `module dhcp` are peer capabilities on the firewall
appliance. Enable DNS before DHCP; remove DHCP before DNS. Reservations and
records are desired state in `/etc/boetticher/lab.yml`; leases are observed
runtime state. Scopes, naming, encrypted upstream DNS, time, tests, and
teardown rules are described in
[Client services](networking/client-services.html).

## VPN

`module vpn` manages one retained AirVPN WireGuard connection on the firewall
appliance and VPN-only egress for declared protected clients. There is no
separate VPN-router guest, and the provider name is not a Module namespace.

```text
boetticher module vpn plan
boetticher module vpn apply --api-key-stdin --yes
boetticher module vpn apply --location Sydney --api-key-stdin --yes
boetticher module vpn apply --yes
boetticher module vpn status --details
boetticher module vpn add-client RESERVATION --yes
boetticher module vpn remove-client RESERVATION --yes
boetticher module vpn teardown --plan
boetticher module vpn teardown --yes
```

First provisioning, or an explicit change of the `--location` selector (a
named server, country, or region; the default is `europe`), reads the AirVPN
account API key once from stdin with `--api-key-stdin --yes`. The key is never
stored in `lab.yml` or arguments. An ordinary reapply uses the retained
root-only tunnel material without account access and refuses a selector
mismatch.

### VPN clients

A VPN client is an existing DHCP reservation in the protected `.224-.239`
address class of its zone. `add-client RESERVATION --yes` declares it VPN-only
and reconciles its source policy; the reservation is never copied or
renumbered. A protected client cannot fall back to ordinary WAN, and the shared
DNS/NTP exceptions stay explicit. `remove-client` refuses while a port forward
still depends on the client, and removing a client never grants ordinary-WAN
fallback because the address-class guard stays in force. Clients and forwards
are recorded under `modules.vpn` in `lab.yml` (see [Media](#media) for an
example forward).

`status` reports the connection and protected-client enforcement separately;
a missing or unusable connection is reported as blocked or unavailable and is
never repaired by status. Provider reboot and VPN teardown inspect the enrolled
Host's complete VM inventory and each running guest NIC before stopping
protection; malformed or unavailable inventory refuses the mutation, while
stopped guests do not block it. Teardown retains client intent, protected
ranges, and reusable account material, leaving protected clients blocked while
disconnected. These are source and local-runtime safeguards; the disposable
protected VPN-client packet journey remains a separate acceptance gate.

## Tailnet

`module tailnet` owns the single fixed subnet-router guest `lab-tailnet-01`
(VMID 200) on TRANSIT. Apply requires enabled DNS and DHCP and reads the auth
key only after approval, from the private file given with `--auth-key-file`.
Repeating apply after native runtime, provider, and intent agreement is a
no-op. Tailnet status is local runtime evidence; remote peer reachability,
split-DNS grants, packet journeys, and physical isolation require separate
acceptance. The guest, route, policy, and recovery contract is described in
[Tailnet](networking/tailnet.html).

## Observability

The installed Controller owns one atomic observability runtime through the
same single-Host path:

```text
boetticher module observability plan|apply|status|test|teardown|secrets
boetticher module logging query|status
boetticher module monitoring status
boetticher module statuspage status
boetticher module monitoring ask QUESTION
boetticher module monitoring incidents list|show|investigate [ID]
boetticher module observability alerts pushover apply|status|test|remove
```

`module observability` creates and reconciles the exact unprivileged
`lab-monitor-01` LXC (VMID 120, VLAN 10) with retained metrics, logs, and
observability state volumes. It owns VictoriaMetrics, VictoriaLogs, Grafana,
Gatus, and the optional explicitly configured Bifrost/Holmes route. Monitoring,
logging, and status page remain read-only facets; they have no independent
lifecycle or runtime ownership. Holmes is configured under Monitoring, and
`module monitoring ask` is the explicit nested monitoring operation.
Teardown stops the whole owned guest and retains its data for a later apply.
Apply provisions the public Caddy frontend and native collection paths. Live
Controller/Host acceptance of that path remains `NOT TESTED`.
Journal upload uses system trust and no client certificate; metrics use
authenticated HTTPS paths through the fixed internal Caddy address. Ingest
accepts only POST `/upload` from the three resolved collection sources and
does not trust forwarded headers. Metrics paths are fixed per target and use
Basic Auth; arbitrary upstream paths are denied.

`status` for observability, logging, monitoring, and status page shares one
30-second read budget. It verifies guest ownership once, reads the guest state,
then checks each required unit (`systemctl is-active`) and, for active units,
its loopback health endpoint in one batched guest command; every unit query and
health request has its own 5-second bound. A unit that is not active or an
endpoint that fails is reported as unhealthy with its own detail. A spent budget
is reported as `status budget of 30s ran out during <check>; health not
determined`, never as an unhealthy provider. `plan` runs the same check over the
full required service set and prints what it checked (for example `7/7 required
services active with healthy endpoints`) before proposing to preserve or
reconcile the runtime; apply still compares the configuration digest before it
skips work.

When Holmes is enabled under Monitoring intent, the same LXC runs the pinned Holmes
0.40 runner and the bounded incident service. Holmes can use only the local
Prometheus-compatible VictoriaMetrics endpoint and VictoriaLogs endpoint.
Bifrost is the sole model route at `127.0.0.1:4000/v1`; its separate
`holmes-client-token` is the only credential Holmes and incident intake receive,
and upstream provider keys remain Bifrost-only. Gatus alerts are accepted only
on the loopback incident webhook; the private report UI is exposed through the
existing Grafana session via Caddy forward-auth. `module monitoring incidents`
lists, shows, and triggers one bounded read-only investigation. The queue is
SQLite-backed, deduplicated, restart-recoverable, retained for 30 days, and
capped at 100 terminal/current records. Each investigation is limited to one
attempt, six tool rounds, five minutes, and the configured model alias.
`module monitoring ask QUESTION` still requires normal operator approval before
a model request that may incur charges. The runner is unprivileged and bounded,
uses pinned localhost routes, and does not save transcripts. Kernel-level LXC
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
boetticher module observability apply --public-domain example.com --yes
```

The Gatus status page uses HTTPS without a password prompt inside the existing
network access boundary. Grafana sign-in and private metrics authentication
remain enabled; no status-page password is required for a fresh deployment.

To opt into Holmes/Bifrost, also set `holmes-client-token` and
`openrouter-api-key`, then apply with an explicitly qualified provider model
(DeepSeek V4.1 Flash is the current candidate; the V4 Flash route remains an
explicit fallback, never an implicit downgrade):

```text
boetticher module observability secrets set holmes-client-token
boetticher module observability secrets set openrouter-api-key
boetticher module observability apply --public-domain example.com --holmes-model deepseek/deepseek-v4.1-flash --yes
```

To import existing operator-held provider material, use stdin or a
credentials file; the filenames are the only values that belong in shell history:

```text
boetticher module observability secrets set openrouter-api-key < ~/.secrets/btcr-openrouter.key
boetticher module observability alerts pushover apply --credentials-file ~/.secrets/btcr-pushover.key --yes
```

The Monitoring intent may cap the paid path explicitly. Defaults are the
approved V1 limits: `daily_budget_usd: 2`, `investigation_budget_usd: 0.25`,
`max_rounds: 6`, `max_queue: 100`, `investigation_deadline_seconds: 300`, and
`retention_days: 30`. The incident service reserves the maximum per-call
budget before invoking a model and fails closed when the daily reservation is
exhausted.

Apply creates only an absent exact guest, refuses foreign or mismatched
identity, uploads the installed provider payload, and verifies the active
provider units and local endpoints. Repeating a healthy apply is a no-op.
`--yes` approves mutation, while an interactive affirmative answer is required
otherwise. Source, package, and offline checks are available locally; live
Controller/Host rollout and live acceptance remain `NOT TESTED`.
Gatus currently checks the shared provider health endpoints; broader lab
outcome checks remain deferred.

## Media

The media application lifecycle uses one fixed amd64 QEMU VM, `lab-media-01`
(VMID 290, `10.10.20.230`, SERVERS VLAN 20), with a 32 GiB root disk and a
configurable persistent media disk on `boetticher-data` (the apply default is
256 GiB). The typed `lab.yml` intent includes:

```yaml
modules:
  media:
    enabled: true
    media_gib: 500 # reference installation override; choose explicitly for other sites
    application_domain: media.example.com
    aliases:
      radarr: radarr
      sonarr: sonarr
      bazarr: bazarr
      prowlarr: prowlarr
      trailarr: trailarr
  vpn:
    clients: [lab-media-01]
    forwards:
      - name: media-qbittorrent
        reservation: lab-media-01
        protocols: [tcp, udp]
        port: 35796
```

The peer forward uses TCP and UDP port `35796` on both the external and guest
side. Before applying, the operator must complete or confirm the matching
AirVPN forwarded-port setup and supply the assigned port in this intent. The
forward is enforced by the live firewall-integrated VPN provider; there is no
separate Boetticher VPN-router guest. The supported operator journey is:

```text
boetticher module media plan
boetticher module media apply --cloudflare-token-file /secure/path/token --yes
boetticher module media status
boetticher module media test --yes
boetticher module media teardown --plan
boetticher module media teardown --yes
```

`plan` and `apply --plan` are read-only and identical in content: they list
each `lab.yml` field apply would save (`field: before -> after`; defaults and
protocol order are not changes), whether the provider DNS/DHCP/VPN
prerequisites already match, the observed guest runtime, and the ordered steps
apply would take (for example starting the stopped VM, which has `onboot=0`, and
redeploying the application). When intent, provider, guest and application
already agree, the plan says apply is a no-op.

The token path must be an operator-owned private regular file. It is staged only
through the authenticated Host and guest agent, then removed; it is not printed,
stored in intent, or included in status. The peer port comes from the existing
`modules.vpn.forwards` entry `media-qbittorrent` and preserves its TCP/UDP
number. The deployed data disk and retained legacy application data are
preserved across reapply and teardown. Applying requires the current
protected-service state and a healthy VPN handshake before the VM or application
starts. A complete protected-guest
inventory is required before provider reboot, VPN teardown, or application
teardown can stop protection; stopped guests are explicitly ignored. These
checks are source and local-runtime safeguards and make no deployment or
packet-acceptance claim.

The VM firewall admits HTTPS only from TRUSTED (`10.10.30.0/24`) and Tailnet
SNAT (`10.10.5.10`); the integrated firewall provider owns peer-forward
provenance. Caddy
rejects unknown service names, Docker forwarding is fail-closed, and IPv6 is
disabled. The Cloudflare token must be scoped to DNS Write plus Zone Read for
the configured application domain. The five configured service aliases plus
`qbittorrent`, `jellyfin`, and `jellyseerr` are published under one wildcard
certificate for that domain;
unknown hosts return 404. `status` reports guest application health and VPN
health separately.
Local runtime checks are evidence for the installed guest only; remote ingress,
peer packet journeys, physical VLAN isolation, and live public acceptance remain
`NOT TESTED` until executed. Teardown stops the VM and removes aliases and the
peer forward while retaining media, its reservation, and VPN client protection.

## Network management access and recovery

The managed firewall keeps inter-zone forwarding disabled for management
access. Its owned rules allow TCP/22 from TRUSTED and the identity-bound
Tailnet router to MGMT, plus TCP/22 from the resolved Controller SERVERS
reservation to the Host at `10.10.99.5`. After the Host path is applied,
re-enroll through the verified internal address to make it the active
Controller connection; the original HOME address and strict imported SSH trust
remain the explicit recovery path.

Recovery retains protected off-component configuration, identities, and
AirVPN/Tailnet credentials, or documents deliberate reprovision; leases are
disposable. Use the existing independent Controller/Host management path; there
is no backup platform, and recovery does not need Host teardown.

Remote Tailnet, packet, physical USB, StreamDeck navigation/reconnect, and the
disposable protected VPN-client journeys remain separate acceptance gates and
are reported as `NOT TESTED` or `HOLD` until their exact journeys execute.
New network modules, an aggregate coordinator, SSO platforms, and switch
automation are deferred.

## Capability, provider, runtime

Keep these concepts separate:

| Concept | Meaning | Examples |
| --- | --- | --- |
| Capability | What the operator manages | firewall, DHCP, DNS, VPN, monitoring, status page |
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
not automatically a Module. See the
[Controller guide](controller.html#status-daemon-and-peripherals).

## Lifecycle boundary

Host configuration is established first with:

```text
boetticher host apply
boetticher host status
```

Host apply owns the Proxmox OS baseline, storage, and virtual networking. It
does not deploy Modules. Each Module chooses a capability name, defines its
bounded action surface, preserves exact ownership, and remains separate from
Host lifecycle and Controller peripherals.
