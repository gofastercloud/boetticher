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

Do not implement DHCP, DNS, status integration, VPN, physical trunking, or
external-switch management during Phase 4A unless a strict implementation
dependency is discovered and explicitly approved.

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
