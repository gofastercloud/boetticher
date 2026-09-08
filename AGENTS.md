# Boetticher: Codex contract

Agent instructions only. Human explanations, command examples, configuration,
and acceptance records belong in README.md and docs/.

## Coordinate efficiently

- Act as coordinator and product owner: own scope, priorities, integration,
  verification, and the final outcome. Delegate implementation to
  `gpt-5.6-luna` and planning/design analysis to `gpt-5.6-terra`.
  Use subagents whenever bounded independent work saves time or tokens;
  keep trivial, tightly coupled, or urgent integration work local.
- Use `gpt-5.6-luna` subagents for all Git-related work, including read-only
  inspection, branching, staging, commits, pushes, pull requests, reviews,
  merges, and cleanup. The coordinator retains scope, authorization, and final
  verification ownership; delegate execution to one Git owner.
- Give each delegate a short brief: outcome, exact read/write scope,
  constraints, acceptance criteria, and return format. Assign disjoint files;
  share only relevant context. Avoid full-history forks, recursive delegation,
  duplicate investigation, and repeated polling. Reuse agents. If a requested
  model is unavailable, disclose the fallback.
- Keep one owner for live systems and Git delivery; delegation grants no new
  authority. Review delegate changes. Returns should contain changed paths,
  checks, findings, and blockers, not transcripts.
  Never restore files to HEAD to undo an agent mistake: revert only your own
  exact edit, preserving concurrent parent/user work; report uncertain overlap.
- Use targeted rg, bounded tool output, and relevant document sections. Batch
  independent reads; avoid rereading unchanged material. Give brief substantive
  progress updates, not repeated plans or command-by-command narration.
- Proactively create focused, reusable skills when required for repository work,
  especially when they reduce repeated investigation, improve token efficiency,
  or improve output quality. This is standing authorization to create those
  skills without separate confirmation. Reuse existing skills where suitable,
  follow the skill-creator guidance, and keep new skills concise and grounded in
  demonstrated needs. Skill creation does not expand authority for the actions
  those skills perform.

## Scope and authority

- Inspect root, branch, status, worktrees, and applicable instructions before
  editing. Preserve unrelated dirty/untracked/ignored work, including dist/.
  Build separately when existing outputs must be retained.
- Use feature branches. Commits, pushes, PRs, merges, deployment, reboot,
  destructive cleanup, and external messages require scoped user authorization.
  Approval persists for ordinary steps in its window; do not repeatedly ask.
  Planning or push approval alone does not authorize deployment or replacement.
- Never reset to an old reviewed SHA, overwrite unpublished fixes, rewrite
  pushed history, or discard dirty worktrees for a clean report. Before approved
  cleanup, verify exact targets, ownership, merge ancestry/patch equivalence,
  unique files, and PR state. Keep ambiguous resources.
- Finish the requested slice and final live state. Never automatically redeploy
  after an acceptance teardown. Honor explicit deferrals without relabeling
  them PASS. Do not reopen accepted peripheral compromises or provider selection.

## Product and CLI

- Controller → one Proxmox Host → first-party Module capabilities. Controller
  runs Boetticher and owns peripherals. Host owns enrollment, SSH trust,
  Proxmox baseline, storage, bridges, inventory, teardown, and reboot.
  Host apply never deploys Modules; Modules consume rather than repair substrate.
  Proxmox owns user workloads; never adopt/import/delete unknown guests.
- A capability is operator intent, not necessarily a VM/package/daemon.
  Firewall/DNS/DHCP share OpenWrt. Delegate through ordinary internal Go calls,
  never recursive CLI execution, hidden aliases, or another API service.
  NTP and DHCP-derived DNS are supporting functions, not capabilities.
- Grammar: `boetticher controller|host <action> [flags]` and
  `boetticher module <capability> <action> [flags]`. Use apply for changes;
  plan/status/list are read-only. Base/foundation and top-level network/DHCP/DNS
  commands are retired. Do not invent a core-services Module.
- Advertise only implemented flags. Leaf help succeeds without enrollment or
  remote calls. Invalid input, refusal, blank response, and EOF cause no mutation.
  Changes use --yes or affirmative confirmation; only a read-only determination
  of no change may bypass approval. Never mutate to discover a no-op.
  Use --plan, not another --dry-run spelling; preserve exact disk/adoption approvals.
- Keep hardware/addresses in reference bindings. Pass Host configuration
  explicitly; no premature multi-Host selectors, placement, or provider registry.
  Roadmap: 4A firewall, 4B client services, 4C VPN, 4D integration/recovery,
  Phase 5 additional capabilities. Future plans do not authorize implementation.

## Intent and shared ownership

- /etc/boetticher/lab.yml owns Host/LAB/capability intent;
  /etc/boetticher/controller.yml owns Controller-local settings. Use existing
  typed readers/writers; preserve every supported section and reject unsupported
  fields. Retain atomic writes, restrictive permissions, path containment, and
  symlink protection.
- Acquire the shared bounded mutation lock BEFORE loading intent. Under it:
  load, prepare/validate, inspect prerequisites/conflicts, confirm, save,
  reconcile, verify. Plan/apply share pure preparation. Defaults initialize only
  approved changes. No-op requires desired, provider, and runtime agreement.
  Identical adds must not conceal pending application failure.
- Saved intent survives failed application: report the partial result and normal
  apply recovery. No rollback journal or duplicate configuration/lease database.
- Coordinate shared dnsmasq settings, time, and capability firewall rules through
  one owner. Reconcile explicit owned objects, never another capability's entries
  by prefix. Handle factory/global sections explicitly. Preserve unrelated state
  or refuse conflict. Reload only affected services.
- Firewall creates the appliance; enable DNS before DHCP. Remove DHCP before DNS;
  refuse appliance removal with enabled dependants. Retain reusable service
  intent and upstream appliance time on service teardown.
- Reservations/records are desired state; leases are observed runtime state.
  Preserve flat canonical naming and native A/PTR ownership, dynamic pools on
  SERVERS/TRUSTED/SANDBOX, reservation-only TRANSIT/INFRA/MGMT, and probe space.
  Validate names/MACs/addresses/pools and active-lease conflicts.

## Deploy and diagnose

- Acceptance uses the normal INSTALLED Controller CLI outside a checkout.
  Install one coherent CLI/status/helper/builder/bootstrap payload through the
  existing procedure. Record source, included dirty changes, and installed build;
  preserved dist/ does not prove current bytes. Invalidate only affected caches.
- Normal operation needs no private site, Age identity, Proxmox API token,
  development override, Mac-copied appliance image, or manual OpenWrt preparation.
  Preserve security in retained legacy code without making it a dependency.
- Use established strict Controller-to-Host SSH and verified HTTPS /ubus.
  Internal bounded Host-native tools are appropriate; provider configuration uses
  its supported API. Read-only exact-VM guest-agent diagnosis is permitted.
  Never expose secrets or weaken SSH/TLS, ACLs, integrity, or ownership checks.
- Preserve Controller identity, Host trust, Proxmox node/boot/data storage,
  vmbr0/HOME, persistent vmbr1, unrelated guests/volumes, and physical networking.
  Never answer HOME DHCP or migrate management/time incidentally. LXCs inherit
  Host time; namespace probes never set clocks. Reboot only the scoped target.
- Diagnose the first failing boundary: boot, network, listener/TCP, TLS, protocol,
  authentication/authorization, runtime. Keep the last meaningful error.
  Retry transient readiness within a measured budget; never conceal failure with
  sleeps, blind credential rotation, weaker trust, or repeated rebuild/install.
- API acceptance does not prove daemon consumption, init enablement, persistent
  storage permissions, or reboot recovery. Use pinned native contracts and real
  response shapes; narrow permissions to required methods/packages.

## Observe and verify

- Shared capability facts feed CLI/Blinkt/StreamDeck. VM-running is not service
  health; unconfigured is off and unknown is not healthy. Status is bounded and
  observational: no repair, full suites, package refresh, or test clients.
- The existing daemon owns peripherals. Measure delays before changing libraries
  or timeouts: synchronous collection itself can block animation/input; an output
  queue alone cannot fix that. Budget sequential checks, bound device I/O, and
  retain input lifetime until close. Peripheral failure cannot gate the lab.
  Test physical input/reconnect independently of rendered output.
- Packet expectations are independent of the renderer. Denials require working
  sources/positive-control targets and executed attempts. Transport/setup/target/
  protocol failures are errors. IPv4-only is not proof of IPv6 leak protection,
  same-VLAN, Wi-Fi, or switch isolation; do not disable household IPv6 incidentally.
- Fixtures never borrow production identities. Own exact processes, files,
  namespaces, interfaces, and temporary reservations. Use isolated client hooks
  and separate positive/unknown-client lease state. Register cleanup immediately;
  run under existing ownership with a fresh bounded cancellation budget.
  Cleanup-only must work without a healthy provider. Recovery removing leftovers
  is not successful automatic cleanup; cleanup failure prevents suite PASS.
- Add focused behavioral regressions for real defects. Run make ci before runtime
  handoff; execute Linux-only tests on Linux, not merely a cross-build.
  Docs-only edits need structure/link/diff checks. After fixes settle, run the
  required closing journey once; don't repeat qualified Host teardown/reboots
  or full ceremonies for wording/display changes.
- GitHub Actions is Pages-only; testing is local unless explicitly changed.
  Do not resurrect retired all-artifact release ceremonies from older documents.

## Keep it small and truthful

- Prefer concrete Go, native services, and small consumer-owned interfaces.
  No speculative frameworks, dependency DAGs, policy DSLs, DDNS synchronizers,
  monitoring stacks, workflow databases, or correctness/audit theatre. Hashes,
  signatures, and reports need real consumers; preserve actual security checks.
  Remove superseded callers/docs within scope, not via repository-wide rewrites.
- Update canonical human docs and generated help together; generate commands.md
  from internal/cli/commands.go. Replace contradictions. Keep AGENTS short:
  no command catalog, incident diary, live inventory, or duplicated standards.
  Historical spike results remain historical.
- Report source checks, deployment, packet journeys, and physical acceptance
  separately. Merge, green LEDs, status PASS, and prior claims cannot prove
  unexecuted gates. Preserve FAIL/HOLD/NOT TESTED and explicit deferrals.
  Use one concise handoff: source/build, verified outcomes, gaps, cleanup, and
  actual final state. No mandatory evidence bundles or log dumps.
- Use direct argv or safe shell quoting. Pass multiline GitHub text through
  temporary body files; backticks and dollar substitutions execute shell code.

Read as needed: README.md/docs/start.md (operator flow), docs/modules.md
(ownership), docs/controller.md/docs/lab.md (bindings), and
docs/networking/firewall-capability.md, client-services.md, openwrt-provider.md
(network contracts). This is a routing list, not a mandatory reading list.
