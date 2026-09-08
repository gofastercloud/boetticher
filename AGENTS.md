# Boetticher: Codex contract

Agent instructions only. Human explanations, command examples, configuration,
and acceptance records belong in README.md and docs/.

## Priority: efficient agent operation

This section has project priority over conflicting guidance later in this file,
while user, system, and developer authority, correctness, security, and
verification requirements remain controlling.

- Minimise aggregate consumption across agents; accept slower work when it
  reduces tokens without weakening correctness or verification.
- Use the lowest suitable model and effort. Use `gpt-5.6-luna` for routine
  research, coding, testing, and browser work; use `gpt-5.6-terra` only for a
  justified deeper review. After demonstrated errors, raise effort or refresh
  the handoff instead of repeating an inadequate pass. Do not default to High.
- Reserve `gpt-6-astra` for orchestration. Consider a manually verified
  handover to `gpt-5.6-sol` for a sustained, settled, bounded backlog. Never
  run Astra and Sol concurrently, and never claim an automatic model switch.
- Use `fork_turns: none`, with a small self-contained objective, exact paths,
  constraints, and acceptance criteria; do not copy history. Reuse one agent
  for related work through acceptance; start a fresh agent for each unrelated
  work package. Child agents are prohibited.
- Work sequentially by default. Use concurrency only when it demonstrably
  reduces total work or rework, or when an explicit deadline requires it.
- Reuse verified authority and evidence within each workstream; refresh it when
  state or gates change. Use one independent review for consequential changes;
  repeat checks only for changed code, a failure, an unresolved concern, or
  required fresh evidence.
- Settle the bounded end-to-end scope and interfaces first, then keep one
  integrator through acceptance. A scaffold, helper, or compile milestone is
  not a working public journey; after an inadequate pass, raise effort or
  refresh the handoff instead of redispatching the same brief.
- Search narrowly, read relevant lines, and keep tool results compact; do not
  retain or emit transcripts. Avoid frequent polling, timers, unchanged status,
  and administrative busywork.
- Progress is normally one sentence and the final is short. At meaningful
  boundaries and before a long wait, report the actual operation and result or
  error; do not silently orphan live work. Keep required receipts on disk and
  provide one compact checkpoint; do not create unsolicited evidence bundles or
  status documents.
- Preserve command exit codes and resumable session IDs when a tool yields;
  empty output is not completion, especially for live deployment commands.
- At meaningful boundaries, check for oversized briefs, duplicate investigation
  or tests, idle wakes, and rework. Record corrective actions only when found.
- Report usage separately as cached input, uncached input, and output. Do not
  report a raw total as an allowance charge or make fixed savings claims.
- Prefer lightweight memory lookup, reuse skill reads, batched independent
  operations, small outputs, and stop checks once gates pass.

## Coordinate efficiently

- Act as coordinator and product owner: own scope, priorities, integration,
  verification, and the final outcome. Delegate implementation to
  `gpt-5.6-luna`; use `gpt-5.6-terra` only for justified deeper review.
  Use subagents only when bounded independent work demonstrably reduces total
  work or rework; keep trivial, tightly coupled, or urgent integration work
  local.
- Use `gpt-5.6-luna` for Git work, including read-only inspection, branching,
  staging, commits, pushes, pull requests, reviews, merges, and cleanup. The
  same Luna integrator may own normal read-only Git/build/test/package checks
  (including incidental Git checks inside `make ci`) and, when explicitly
  authorized, Git delivery; a separate Git agent is not required and is not a
  reason to split a coherent implementation. The coordinator retains scope,
  authorization, and final verification ownership.
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
- Keep one integrator for a tightly coupled operator journey. Dispatch,
  wiring, material, routing, lifecycle, payload, and the required signatures or
  context plumbing belong to that authorized end-to-end slice; a helper-only or
  compile-only milestone is not completion.
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
- Send one-sentence updates and a short final with full receipts on disk when
  needed. Use one compact checkpoint; do not create status-document clutter.
- At meaningful boundaries, check for oversized assignments, duplicate work,
  repeated tests, idle wakes, and rework; record only corrective actions.
  Distinguish cached from uncached input and output tokens; totals are not
  charges, and do not claim fixed savings.
- The coordinator owns scope, priorities, integration, and final verification.
  Git-related work, including read-only inspection, belongs to one
  `gpt-5.6-luna` Git owner; keep one owner for live systems and Git delivery.
  Delegation grants no new authority. Preserve existing authorization limits,
  concurrent changes, and no-reset constraint. Review delegate changes and
  return changed paths, checks, findings, and blockers. Use focused reusable
  skills when needed under their standing authorization; skills do not expand
  action authority. If a requested model is unavailable, disclose the fallback.
- Never restore files to HEAD to undo an agent mistake: revert only your own
  exact edit, preserve concurrent work, and report uncertain overlap.
- Creating focused reusable skills is authorized when demonstrated repository
  needs justify it. Reuse existing skills first and follow skill-creator guidance;
  this grants no authority for the actions those skills describe.
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
- Complete routine discovery, prerequisite wiring, and preparation within the
  granted scope. Pause before any action lacking authority or a genuinely
  missing decision or external dependency; when an operation has failed, report
  its exact error and the smallest resolution. Do not treat routine plumbing as
  a blocker or ask again for authority already granted.

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
  Roadmap: 4A firewall, 4B client services, 4C VPN dependency, 4D Tailnet,
  4E integration/recovery, Phase 5 additional capabilities. Future plans do
  not authorize implementation.

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
- Compose the complete desired state for plan, apply, and no-op, including
  enabled peers and VPN material. Separate healthy existing prerequisites from
  owned pending deltas; verify provider drift and native runtime state, not only
  guest health. Reviewed diffs and staged mutations must use the same explicit
  ownership scope, and teardown must retain peer and foreign objects.
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
- Once scoped live fix-forward authority exists, diagnose the first failing
  boundary on the exact owned target, make the smallest reversible correction,
  test there, backport it to source, and perform one coherent final package and
  deploy after fixes settle. Never leave source and runtime divergent or weaken
  safety, SSH, TLS, integrity, or ownership checks.
- Namespace, sysctl, and readiness commands can return zero while the operation
  failed; read back the actual value and preserve the first failing boundary.
  Establish packet positive controls before counting denials. Prefer isolated,
  least-privilege profiles with explicit container-scoped sysctls and veth peers
  over SYS_ADMIN or disabled security profiles; never bake task-specific images
  or addresses into general contracts.
 - Model retained-state failures separately: a stopped backend and a stopped
   daemon require different native operations. Preserve identity and repair the
   owning service; do not rebuild or reuse keys for an authentication-only issue.
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
- Add focused behavioral regressions for real defects and for the selected
  public command journey; prove fixture setup and positive controls before
  counting denial results, and prevent legacy-handler fallthrough. Compare the
  candidate's absolute path, build ID, compiler, and checksum rather than a
  preserved dist/ filename. Run make ci before runtime handoff; execute
  Linux-only tests on Linux, not merely a cross-build.
- Test the selected public command's dispatch and arguments so positionals cannot
  be swallowed by generic parsers or legacy fallthrough. Exercise native JSON
  response shapes, whitespace, missing fields, and error-return API changes;
  use a fake PATH to prove shell argv, stdin, quoting, and cleanup rather than
  string matching or minified-only fixtures.
 - Add focused behavioral regressions for real defects. Run the actual formatter
  and make ci before runtime handoff; execute Linux-only tests on Linux, not
  merely a cross-build. Freeze the candidate before the required closing gate;
  distinguish a failing target from warnings or tool restrictions, keep a concise
  receipt on disk, and do not repeat kernel or aggregate ceremonies for
   format/docs-only changes when qualified behavior is unchanged.
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
- Reuse qualified baseline evidence. Run changed checks while iterating, then
  the required final source gate and payload build on the coherent candidate;
  do not repeat aggregate ceremonies without a demonstrated defect or scoped
  selected-path requirement. Verify exact owned resources before claiming cleanup.
- Use direct argv or safe shell quoting. Pass multiline GitHub text through
  temporary body files; backticks and dollar substitutions execute shell code.
- Before rebasing or merging, protect dirty tracked, untracked, and ignored
  outputs and preserve both capabilities' new contracts and signatures. Use
  exact refs or SHAs for backup and cleanup; an explicit user discard decision
  may bypass redundant preservation analysis.

Read as needed: README.md/docs/start.md (operator flow), docs/modules.md
(ownership), docs/controller.md/docs/lab.md (bindings), and
docs/networking/firewall-capability.md, client-services.md, openwrt-provider.md
(network contracts). This is a routing list, not a mandatory reading list.
