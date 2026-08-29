# Boetticher agent guide

This is the concise contributor contract. Product and qualification detail
belongs in `README.md` and `docs/`; these rules prevent unsafe or generic
control-plane changes.

## Product and operator experience

- Boetticher is an opinionated Proxmox homelab appliance, not a generic
  orchestrator.
- Prefer fixed, safe defaults, derivation, and deletion over optionality.
  Every operator-visible setting must explain why Boetticher cannot safely
  choose it.
- Keep normal operation small and obvious: `init`, `deploy`, `status`,
  `module configure`, `doctor`, and `update`.
- Do not require routine SSH, hand-edited YAML, Proxmox CLI, Ansible, Go,
  Git, or artifact-builder knowledge for normal operation.
- Keep recovery, destructive, physical-network, and debug operations available
  as advanced guarded paths, with explicit confirmation at trust and
  destructive boundaries.
- Modules are bounded first-party capabilities compiled into the release, not
  plugins, arbitrary workloads, generic ingress, or generic policy DSLs.
- Proxmox owns user workloads. Boetticher never adopts, imports, or deletes
  unknown guests.
- Keep the external Pi/StreamDeck companion outside the in-cluster module
  model.

## Architecture and ownership

- `internal/model` is the canonical typed v3 contract. Desired configuration
  is authoritative; generated files, observations, and evidence are derived
  projections, never competing authorities.
- Preserve deterministic revisions, fixed VMIDs and addresses, ownership
  ranges, and the v3 topology: HOME `vmbr0`; VLAN-aware `vmbr1`; VLANs 5,
  10, 20, 30, 40, and 99.
- The managed Debian gateway owns routing, NAT, nftables, Kea DHCP/DDNS, and
  the inter-zone boundary. External mode publishes a contract only.
- DNS is mandatory and has one built-in implementation: Blocky. Do not add
  provider selection or generic DNS lifecycle paths.
- Core owns privileged mutation, platform secrets, fixed resource identities,
  appliance artifacts, persistent storage lifecycle, and replacement policy.
  Modules declare bounded needs and placement only.
- Appliance artifacts select application software. Ansible performs bounded
  site configuration and verification; it does not replace artifact-selected
  software.
- Official artifacts require deterministic definitions and verified content
  digests. `make image-check` is static validation; `make images` is real
  construction. Metadata and provenance do not become desired-state inputs.

## Security and lifecycle

- Fail closed on trust, ownership, destructive, ambiguous, malformed, and
  incomplete states. Preserve `PASS`, `FAIL`, `HOLD`, `NOT TESTED`, and
  `INCONCLUSIVE` as evidence semantics.
- Preserve strict SSH host identity and authenticated bootstrap key enrollment;
  never use trust-on-first-use as a deployment shortcut.
- Preserve SOPS/Age ownership. Never put secrets in argv, logs, JSON, portal
  output, generated public documentation, or plaintext temporary files.
- Use atomic writes and path/symlink containment for desired state, generated
  state, archives, and sensitive files.
- Prove exact Boetticher ownership before destructive Proxmox or storage
  operations. Persist recovery and purge intent before live mutation, verify
  absence, and leave recoverable explicit `HOLD` state on partial failure.
- `deploy` is the sole normal live-application command. `update` changes
  desired state only and must persist it safely before refreshing projections.
  `preflight --live` is read-only; persistence requires `--record`.
- Temporary privilege and root access require bounded lifetime, cancellation,
  and guaranteed cleanup. Cleanup failure is blocking evidence.
- Live claims require live evidence. Source tests, generated configuration,
  screenshots, cached artifacts, and operator observation do not prove a
  deployment, journey, or qualification gate.

## Go engineering

- Prefer concrete, boring, idiomatic Go and cohesive packages. Do not split
  packages by file size alone.
- Keep interfaces small, consumer-owned, and tied to a real effect boundary;
  accept interfaces where useful and return concrete types.
- Prefer standard-library types such as `io.Writer` over bespoke one-method
  interfaces when semantics are identical.
- Do not introduce DI containers, repositories, factories, generic managers,
  providers, plugin frameworks, or broad helpers without a concrete current
  requirement and a demonstrated reduction in complexity.
- Avoid `map[string]any` and stringly typed state except at genuine dynamic
  boundaries. Use typed enums and values where they clarify contracts.
- Propagate `context.Context` through I/O and process boundaries. Bound
  subprocess output and external waits; preserve explicit cancellation and
  cleanup.
- Execute direct argv, not shell interpolation. Keep ordered lifecycle work
  ordered unless concurrency has a measured, safe benefit.

## Tests, documentation, and delivery

- Add a focused regression test before fixing a behavior or security defect.
  Preserve independent negative/security/lifecycle coverage when simplifying.
- Use strict fakes for external boundaries. Use race or fuzz tests selectively
  at meaningful concurrency, parser, and containment boundaries.
- Run `make ci` before handoff. Local checks prove source behavior only;
  report remote, deployed, journey, and product evidence separately.
- Keep normal documentation focused on operator outcomes and advanced docs
  focused on evidence and recovery. Do not document commands or options the
  binary does not support.
- Inspect the complete staged diff. Keep commits cohesive and imperative,
  preserve unrelated changes, and never commit directly to `main`.
- Do not broaden scope during a qualification fix. Make the smallest
  source-backed change tied to observed evidence, and leave deferred work
  deferred.
