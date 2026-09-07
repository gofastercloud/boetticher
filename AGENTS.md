# Boetticher agent guide

This is the contributor contract for the small, opinionated Proxmox appliance.
Product and qualification detail belongs in `README.md` and `docs/`; these
rules keep the Controller/Host/Module boundary explicit.

## Product model

The supported product is:

```text
Controller
    |
    v
Proxmox Host
    |
    +-- Module <capability>
    +-- Module <capability>
```

- Controller is the machine running Boetticher. The current reference is a
  Raspberry Pi, but generic code and operator documentation use `Controller`.
- Host is the one currently supported Proxmox machine. Host owns trust,
  enrollment, the Proxmox OS baseline, storage, virtual networking, later
  physical LAB networking, inventory/status, teardown, and reboot.
- Module is an operator-visible capability on the Host. Modules are bounded
  first-party capabilities, not plugins, arbitrary workloads, generic ingress,
  or a policy DSL. Proxmox owns user workloads; Boetticher never adopts,
  imports, or deletes unknown guests.

There is no supported `base` or `foundation` product object. Storage and
networking are Host configuration. Do not add lifecycle, status, reboot,
correctness, or evidence machinery for either retired noun.

## CLI contract

Core commands use exactly two levels:

```text
boetticher <target> <action> [flags]
```

The normal Controller/Host targets are `controller` and `host`. Host actions
include `create-identity`, `show-public-key`, `import-host-key`, `enroll`,
`apply`, `status`, `plan-storage`, `teardown`, and `reboot`.

Modules use the one deliberate third-level namespace:

```text
boetticher module <capability> <action> [flags]
```

Capability names describe operator intent (`firewall`, `dhcp`, `dns`, `ntp`,
`vpn`, `monitoring`, `statuspage`, `printer`), not provider-specific or runtime
names. Phase 4 network services are delivered capability-first. OpenWrt is the
current provider implementation, not a public Module namespace. The supported
Module UX is `boetticher module <capability> <action>`.

For Phase 4A, the firewall capability owns its provider lifecycle and consumes
Host-owned `vmbr1`; it must not silently create, repair, or re-own Host
substrate. Normal provider management uses verified HTTPS `/ubus` and UCI. Do
not use SSH mutation, LuCI automation, direct provider configuration-file
editing, or ad-hoc shell mutation as the normal lifecycle. Preserve unrelated
provider-native state by owning deterministic semantic sections rather than
replacing whole configuration packages. Prefer direct desired-state
generation over provider frameworks, policy compilers, or reconciliation
engines. `apply` is the normal mutation verb and a correct repeat is a
semantic no-op. `status` is a cheap operational view; `plan` reports meaningful
operator-visible changes rather than implementation-level diff noise.

Do not expose OpenWrt, UCI, rpcd, firewall4, dnsmasq, Stubby, or other provider
nouns in normal capability UX unless the operator genuinely needs them. Avoid
hashes, manifests, evidence stores, generation counters, shadow inventories,
and other audit machinery without a concrete operational requirement.

Do not implement DHCP, DNS, VPN, physical trunking, or external-switch
management during Phase 4A unless a strict implementation dependency is
discovered and explicitly approved. The simple existing Controller status
projection for the firewall is approved: use the existing status model,
polling, debouncer, Blinkt slots, and StreamDeck Host-detail slots. Keep DHCP,
DDNS/NTP, and DNS explicitly RED until their capabilities are implemented; do
not add a status database or a second scheduler.

Canonical verbs are `bootstrap`, `enroll`, `apply`, `status`, `plan`,
`teardown`, `reboot`, and `test`. `apply` is the declarative Host operation;
repeating correct state is a successful no-op. Do not expose `prepare`,
`initialize`, `configure`, `provision`, `reconcile`, or `converge` as public
synonyms for `apply`.

`status` is read-only. `--details` expands status; `--verbose` is diagnostic
verbosity where a command needs it. Use `--yes` for ordinary approval,
`--data-disk` for exact destructive disk binding, and one Host-oriented
`--adopt-existing-network` flag for explicit internal-bridge adoption. Do not
retain `--confirm`, `--approve`, `--non-interactive`, or
`--confirm-storage` as ordinary-approval synonyms.

## Authority and bindings

- `internal/model` is the canonical typed contract. Desired configuration is
  authoritative; generated files, observations, and evidence are projections.
- Keep Controller-specific intent in `/etc/boetticher/controller.yml` and Host
  intent in `/etc/boetticher/lab.yml`.
- Preserve deterministic revisions, fixed ownership ranges, the protected HOME
  `vmbr0` path, the VLAN-aware `vmbr1` path, and semantic VLANs 5, 10, 20, 30,
  40, and 99.
- Generic code uses roles and bindings. Raspberry Pi, Lenovo, disk model,
  address, NIC, and exact `/dev/disk/by-id` values are reference-lab bindings,
  not architecture. Do not add public `--host`, `--node`, `hosts:`, `cluster:`,
  or host selectors during Phase 3D.
- Keep singleton assumptions local: pass Host configuration explicitly to Host
  operations; do not add package globals such as `CurrentNode`, `HostAddress`,
  or `DataDisk`. Multi-Host UX is not implemented.
- Blinkt, StreamDeck, display, kiosk, and similar peripherals remain
  Controller implementation details, not Module namespaces.

### Controller UX

- `boetticher-status.service` is a lightweight, self-contained Controller
  convenience for the fixed eight-pixel Blinkt layout; it is not monitoring,
  qualification, or evidence machinery.
- The status daemon owns Blinkt exclusively. Controller operations send
  best-effort status/progress events rather than writing GPIO directly.
- Status checks are simple, read-only, and infrequent. They must not depend on
  Pulse, Prometheus, Loki, Alertmanager, Gatus, a logging Module, or an
  external observability system.
- Blinkt or status-daemon failure must never gate Controller, Host, or Module
  operations.
- The fixed operator layout is `CTL HOST FW DHCP/NTP DNS NET CTRL-UPDATES
  HOST-UPDATES`; Controller and Host update indicators are read-only status,
  not update or reboot workflows.
- Controller update status may be green with no available updates, amber for
  pending updates or the native reboot-required marker, or blue for an
  explicit Boetticher configuration-staged event. Host update status may be
  green with no Proxmox update/reboot requirement or amber when one exists.
- Host Internet ping checks may run every 60 seconds, but the full speedtest
  runs from the enrolled Host no more than hourly. Do not refresh APT lists,
  install packages, or reboot from a status check.
- Controller bootstrap always installs the status daemon and Host apply always
  installs the release-built Host speedtest helper. Blinkt and StreamDeck are
  optional peripherals: absent hardware may be reported as `NOT TESTED` or
  retried by its service, but never blocks Controller or Host setup.
- The attached StreamDeck, when enabled, is owned by `boetticher-status.service`
  and is read-only navigation/inspection. It must reuse the shared coarse
  status, Internet, and operation state; detailed Host telemetry may be cached
  separately in memory. No StreamDeck input may reach mutation, shell, or
  Proxmox-credential paths.
- Do not add hashes, manifests, evidence, persistent status databases, or
  synthetic monitoring journeys to improve LED correctness. Future Controller
  peripherals should consume the shared status snapshot rather than becoming
  Modules.

## Safety and lifecycle

- Fail closed on trust, ownership, destructive, ambiguous, malformed, and
  incomplete state. Human-facing asserted checks and operations are binary
  `PASS` or `FAIL`; retain richer internal diagnostics without presenting them
  as operator outcomes.
- Preserve strict SSH host identity and authenticated enrollment. Never use
  TOFU, `ssh-keyscan`, disabled host-key checking, or secret values in argv,
  logs, JSON, generated output, or plaintext temporary files.
- Host apply inspects native state before mutation and stops at trust,
  destructive storage, and ambiguous network-adoption boundaries. It never
  deploys Modules.
- Host teardown removes only exact Boetticher-owned Host state and preserves
  Controller configuration, imported Host trust, Proxmox installation, boot
  storage, HOME management, and independent recovery access. Do not weaken the
  twice-qualified teardown/rebuild behavior.
- `host status` and `host plan-storage` are read-only. The retained guest IPv6
  bridge regression uses reserved temporary VMIDs, proves both directions,
  explicitly stops and destroys guests, and verifies VMIDs and temporary
  volumes are absent, but it is internal to the current vmbr1 implementation,
  not a supported Host command or acceptance journey.
- The current reference architecture is IPv4-only. IPv6 forwarding and
  security policy belong to explicit future firewall/network Module work and
  must not be inferred from the internal bridge regression.
- Do not add persisted workflow state, resume tokens, plan digests, mutation
  ledgers, transaction databases, or generic rollback engines for Host apply.

## Engineering

- Prefer concrete Go and small consumer-owned interfaces. Avoid generic
  managers, provider registries, plugin frameworks, and stringly typed state
  without a current concrete consumer.
- Fix defects at the narrowest ownership boundary. Add focused regression tests
  for behavior or security changes, including negative and cleanup paths.
- Propagate contexts through I/O and process boundaries and execute direct argv.
- Preserve SOPS/Age ownership and atomic writes/path containment for desired,
  generated, archive, and sensitive files.
- Keep appliance artifacts authoritative for application software. Ansible
  performs bounded site configuration and verification; it does not replace
  artifact-selected software.

## Verification and delivery

- Run `make ci` before handoff. Report local, remote, deployed, journey, and
  product evidence separately; source tests and generated configuration do not
  prove live deployment or qualification.
- Preserve `PASS`, `HOLD`, `FAIL`, `NOT TESTED`, and provisional status in
  evidence. Never turn CI, a PR, screenshots, or source review into live proof.
- Keep diffs narrow, preserve unrelated dirty/untracked state, inspect the
  complete diff, use feature branches, and never commit directly to `main`.
- Do not commit, push, open a PR, merge, deploy, message, or delete branches
  unless explicitly requested.
