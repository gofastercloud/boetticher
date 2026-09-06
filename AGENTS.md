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
`apply`, `status`, `plan-storage`, `test-ipv6`, `teardown`, and `reboot`.

Modules use the one deliberate third-level namespace:

```text
boetticher module <capability> <action> [flags]
```

Capability names describe operator intent (`firewall`, `dhcp`, `dns`, `ntp`,
`vpn`, `monitoring`, `statuspage`, `printer`), not provider-specific or runtime
names. Phase 3D documents this grammar only; do not
start firewall or speculative Module implementation in this phase.

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
- `host status` and `host plan-storage` are read-only. `host test-ipv6` must
  use reserved temporary VMIDs, prove both directions, explicitly stop and
  destroy guests, and verify VMIDs and temporary volumes are absent.
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
