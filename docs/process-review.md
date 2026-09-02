# Boetticher process review

## Scope and conclusion

This is a source-forensic review of the `process-review` branch at commit
`8030c60` (the branch was created from the then-current `0.4.2` tip). It covers
the normal lifecycle, module, control-plane, verification, network-test,
artifact, Ansible, persistence, and evidence paths. It does not claim live,
remote-CI, deployment, or product-acceptance evidence.

The short version is that the project is over-engineered in its *composition
of safeguards*, not because the individual safeguards are generally foolish.
The valuable checks cluster at real boundaries: desired-state validity,
ownership, artifact provenance, host identity, destructive operations,
temporary privilege, atomic persistence, and live acceptance. The main waste is
that the same already-typed desired state is revalidated by nearly every plan
builder and projection renderer. A typical live deploy performs approximately
60 whole-site validation-equivalents before counting module loops, Ansible
assertions, SSH retries, remote readiness polling, or health checks. That is a
large amount of defensive ceremony around a small site, and most of it is
hidden from the operator.

The highest-leverage simplification is a single, operation-local validated
snapshot containing the canonical site, revision, derived plans, resolved
artifacts, and secret cache. It should be a small internal value passed to
plan/render consumers, not a generic manager or new policy framework. This
would remove repeated pure local work while preserving checks at trust and
mutation boundaries.

## Counting method

“Whole-site validation-equivalent” means one execution of `Site.Validate`,
including a transitive call made by a provider plan. It is a source-derived
count, not a benchmark counter. A plan may also validate its own narrower
input, parse a file, inspect a guest, run an Ansible assertion, or retry a
remote command; those are reported separately.

The counts below use these conventions:

* `Compose` means `modules.Compose`, which ends with a canonical
  `Site.Validate` after resolving modules and declarations.
* Provider counts include transitive validation. The important examples are
  `proxmox.PlanFromSite = 3`, `firewall.PlanFromSite = 2`, and
  `ansible.Variables = 7` whole-site validations.
* A loop over enabled modules, guests, endpoints, secrets, or probes is shown
  symbolically because its size depends on the site. A retry ceiling is not
  counted as an execution unless the path is taken.
* “Theatre” means a check that adds little independent assurance at that point,
  not that it is useless everywhere. A validation can be valuable once and
  theatre on its fifth repeat.

## Executive assessment

### Keep the safeguards

These checks prevent real classes of operator pain and should remain, although
some can be moved behind a shared validated snapshot:

* Strict YAML shape, known fields, API version, module registration, fixed
  zones/VLANs, reserved identities, safe hostnames, address/MAC parsing, and
  collision checks in `internal/model/model.go:873-1382` and
  `internal/model/yaml.go:15-113`.
* Ownership proofs for guests, VMIDs, names, tags, retained modules, builder
  VMs, storage content, and destructive purge targets. Unknown Proxmox guests
  are not adopted or deleted (`internal/proxmox/audit.go:198-240`).
* Artifact evaluator, definition, content digest, qualification-input, and
  path-containment checks (`internal/artifacts/evidence.go:139-186` and
  `internal/artifacts/catalog.go:532-557`). These are supply-chain controls,
  not UX theatre.
* Strict SSH execution configuration, known-host pinning, bastion policy,
  bootstrap endpoint checks, and host-key readback. A failed identity check
  should be painful; silently connecting to the wrong machine would be worse.
* Separation of static readiness from live prerequisites; root/client guards;
  exact USB and dedicated-storage checks; remote node/API identity comparison;
  and live re-observation after network or storage mutation.
* Bounded temporary root authority, cancellation, exact-owner cleanup, and
  cleanup failure as blocking evidence (`internal/cli/converge.go:1032-1095`
  and `1606-1655`).
* Atomic desired/secret persistence and rollback in
  `internal/site/site.go:80-110`, plus purge intents and target matching in
  `internal/site/purge.go`.
* Live gateway readiness, DNS readiness, mTLS positive/negative journeys,
  upstream observation before publication, and post-mutation verification.
  Local rendering cannot prove any of those.

### Collapse or demote repeated work

These are the clearest candidates for simplification:

1. Every provider plan independently calls `Site.Validate`. The same canonical
   object is checked again by firewall, DNS, Pulse, backup, storage, logging,
   USB export, Proxmox, Ansible, SSH, and portal consumers.
2. `writeModelProjections` invokes roughly 20 whole-site validations for one
   projection refresh. Deploy calls it before and after the main convergence
   work, so projection generation alone accounts for roughly 40 validation
   equivalents in a configured bootstrap path.
3. `ansible.Variables` performs seven validation-equivalents and recursively
   rebuilds several provider plans. `proxmox.PlanFromSite` performs three.
4. Module configuration composes the current site, proposed site, and
   before/diff site. DNS mutation composes current, proposed, and post-save
   state. These are defensible rollback boundaries, but the same pure local
   work is repeated.
5. The YAML parser performs three decode passes. The first two improve error
   classification and shape checking, but the marginal value should be tested
   against a single strict decode with a small preflight for API version and
   shape.
6. `Registry.Validate` runs on every registry resolution even though the
   first-party registry is immutable process data. It is cheap, but repeated
   registry validation adds ceremony to every composition.
7. The platform secret cache is only partial. Deploy loads the cache and later
   performs separate full secret loads for values that could be part of the
   same operation-local cache.
8. Doctor reads 16 revision-bearing artifacts independently and tests each
   with `strings.Contains`. That is both noisy and a weak freshness proof.
9. `verify` collects checks and writes `verification.json`, `status.json`, and
   sometimes the portal. That is a surprising mutation for a command whose
   name sounds observational.

### Correctness problems, not just overhead

The review found several places where simplification should not mean removing
the check; the existing structure needs tightening:

* `internal/site/site.go:37-55` composes and validates the active site before
  attaching retained modules and pending DNS deletions. Retained-module
  validation checks each retained guest, but does not appear to perform a full
  cross-collision check against the newly composed active components. This is
  a state-boundary gap worth a focused regression test.
* `internal/modules/compose.go:54-107` silently skips invalid Gatus endpoint
  URLs while deriving endpoint intents. A malformed declarative URL should
  normally fail composition rather than quietly remove monitoring/network
  intent.
* `internal/cli/module_configure.go:834` ignores an error from composing the
  `before` state while producing a configuration diff. That is not a harmless
  convenience: a failed baseline can be presented as an empty or misleading
  diff. It should fail closed.
* `internal/cli/verify.go:238-268` initializes every evidence tier to
  `TierLocal` and overrides known check names. A newly added or renamed check
  can therefore receive an incorrectly optimistic evidence tier. Unknown
  checks should be rejected or explicitly marked unclassified.
* `internal/cli/verify.go` and `internal/cli/helpers.go:312-320` use a revision
  substring check for projection freshness. This can produce false positives
  and proves neither artifact structure nor semantic identity. It is adequate
  as a cheap hint, not as an audit proof.
* Network-probe reports retain `INCONCLUSIVE`, but terminal output maps every
  non-`PASS` result to `FAIL`. That hides uncertainty precisely where an
  operator needs to know that a result was not proven.
* `runModuleChangeWithInput` writes the desired module change and then invokes
  the full deploy. If deployment fails, desired state is intentionally changed
  but not necessarily converged. That may be the intended model, but the
  command couples two materially different operations and should make the
  recovery state explicit. `module configure` uses the opposite, separate
  deployment model, which makes the UX inconsistent.
* Doctor exposes `HOLD`, `NOT TESTED`, and `INCONSISTENT` while the project
  contract says human-facing asserted checks should be binary `PASS`/`FAIL`.
  Rich internal evidence is good; the operator contract needs one deliberate
  rule rather than two competing ones.

## The core validation graph

The canonical flow is sound but repeats its root gate at almost every leaf:

```text
YAML parse and shape checks
        |
        v
module registry validation and dependency resolution
        |
        v
BaseSite -> Site.Validate
        |
        +--> DNS plan
        +--> firewall plan -> DNS plan
        +--> storage plan
        +--> backup plan
        +--> logging plan
        +--> Pulse plan
        +--> USB plan
        +--> Proxmox plan -> storage + USB plans
        +--> Ansible variables -> DNS + Pulse + firewall + logging + USB
        +--> SSH rendering and bastion policy
        +--> portal build
```

The problem is not the dependency graph itself. It is that each arrow invokes
the root gate again instead of consuming a validated result. For example:

| Consumer | Source | Site validation-equivalents per call | Assessment |
|---|---|---:|---|
| `dns.PlanFromSite` | `internal/dns/dns.go:112` | 1 | Valuable boundary once; repeated calls are theatre. |
| `firewall.PlanFromSite` | `internal/firewall/plan.go:105-157` | 2 | Local firewall and DNS invariants are valuable; root repeat is not. |
| `storage.PlanFromSite` | `internal/storage/storage.go:65` | 1 | Valuable before storage mutation; redundant within one operation. |
| `proxmox.PlanFromSite` | `internal/proxmox/plan.go:355` | 3 | Valuable before Proxmox mutation; high repeat amplification. |
| `ansible.Variables` | `internal/ansible/ansible.go:259` | 7 | Biggest pure-local multiplier. |
| SSH render | `internal/sshconfig/sshconfig.go:39` | 1 | Keep output-specific validation; consume snapshot root. |
| bastion policy | `internal/sshconfig/sshconfig.go:104` | 1 | Keep security-specific validation; avoid root repeat. |
| portal build | `internal/portal/portal.go:36-83` | 1 | Keep artifact/publish checks; root repeat is theatre. |

`internal/modules/compose.go:11-51` is the right place to establish the
canonical site. `internal/cli/helpers.go:50-201` is the right place to build a
single projection context. The current implementation instead reconstructs
each plan independently.

## Command accounting

### Summary table

The following are typical source-derived counts. “With portal” means the
command has a configured bootstrap endpoint and rebuilds the operator portal.

| Command/path | Whole-site validation-equivalents | Other correctness work and operator effect |
|---|---:|---|
| `config validate` | 1 | YAML parse, registry resolution, module/declaration validation. Reasonable. |
| `config show` | 1 | Same composition before rendering. Reasonable, though `show` is not purely a file dump. |
| `preflight` offline | 4 | `site.Load` + firewall plan (2) + USB plan (1), plus tool/version, credential, mode, and readiness checks. |
| `preflight --live --record` | 5 | Adds live device checks, endpoint DNS, physical discovery, persistence, and portal build. |
| `deploy --dry-run` | about 8 | Load (1), firewall plan (2), Proxmox plan (3), static readiness (1), USB plan (1). No remote mutation. |
| typical managed `deploy` | about 60 | Two projection refreshes contribute about 40. Add remote waits, guest inspection, Ansible, artifact checks, health journeys, and cleanup. Branch/configuration dependent. |
| `verify` offline | 11 | Canonical load plus offline firewall/DNS/Pulse/backup/storage/qualified-Proxmox/bastion plans. Writes verification/status; portal adds 1. |
| `status` offline | 11 | Same health collection without verify’s evidence/portal writes. |
| `verify --live` managed | about 15, or 16 with portal | Adds live gateway planning: status, upstream observation, ruleset comparison, publication checks. |
| `doctor` offline | 8 | Load, three platform-ownership plan validations, qualified evidence/Proxmox plan (3), storage plan. Also reads 16 projection files. |
| `doctor --live` managed | about 14 | Adds live gateway plan (2), qualified plan (3), storage plan, node/guest/network probes; optional AIOps nests another load. |
| `network test` normal | 5 | Load + explicit `Site.Validate`, firewall plan (2), storage plan; then temporary guest identity/network tests and mandatory cleanup. |
| `network test --cleanup-only` | 2 | Load plus explicit validation; exact ownership cleanup still matters. |
| `module configure` | 3 `Compose` operations | Current, proposed, and before/diff state; USB observation, secret declarations, dependency prompts, confirmation. |
| normal module enable/disable | 3 `Compose` operations before deploy | Modified state, old state, then deploy’s new load; purge adds Proxmox plan and destructive proof. |
| DNS add/remove | 3 `Compose` operations | Current, proposed, post-save reload; atomic rollback is valuable, but hidden latency is high. |
| DNS record add/remove | 2 `Compose` operations | Current and proposed; optional live guest identity proof when using VMID. |
| firewall rule add | 1 `Compose` plus direct resolved validation | Optional live guest identity/address proof. Remove is asymmetrical and does not recompose the current site. |
| confirmed version update | 2 `Compose` + 1 bare config validation | Adds about 20 projection validations and portal build; rollback can repeat them. |
| cold bootstrap | about 31 | Three Proxmox planning points, one 20-validation projection refresh, portal, artifact qualification, physical/network/trust checks. |
| `bootstrap endpoint set` | about 22 | Load + 20 projection validations + portal. Excessive for a single endpoint setting. |

These counts are not a claim that `Site.Validate` is computationally
expensive in every run. They show how many independent callers believe they
must re-establish the same invariant. The user-visible pain comes mainly from
the associated file reads, YAML/JSON work, crypto, artifact hashing, remote
SSH, and repeated plan construction.

### `deploy`

`internal/cli/converge.go:48-1027` has the most complete correctness story and
the largest amplification.

The phases are coherent: load and revision, static plan/readiness, live
prerequisites, credentials and PKI, Proxmox convergence, appliance bootstrap,
networking, services, health journeys, and persistence. The deployment report
also preserves phase duration, mutation scope, uncertainty, and cleanup
failure (`internal/cli/deploy_report.go:18-263`). This is useful audit data.

The local validation repetition is roughly:

* Initial `site.Load`: one composition and canonical validation.
* Initial firewall plan: two.
* Backup and storage plans: one each.
* Proxmox plan: three.
* Static readiness: direct site validation plus USB plan: two.
* Ansible variables: seven.
* First projection refresh: about 20.
* Live prerequisite USB plan: one.
* DNS plan: one.
* Final projection refresh: about 20.
* Portal build: one.

That totals about 60. It excludes optional AIOps composition, the per-module
loops, the second root SSH wait after identity configuration, and all retries.
The source does make one good performance choice: guest state inspection is
parallel and bounded, and `inspectDeploymentGuestStates` avoids duplicate
guest reads (`internal/cli/converge.go:1156-1210`). The project should apply
the same discipline to local plan construction.

The remote checks are mostly valuable, but the UX has several stacked waits:

* `waitForDeploymentRoot` reads/pins the host key, performs an initial SSH
  attempt, then can re-arm root access up to three times with up to 30 SSH
  polls and two-second spacing.
* The root wait occurs early and again after identity configuration.
* Each managed LXC can receive its own host-key/readiness loop.
* Gateway readiness is verified after bootstrap and again after publication;
  DNS has a dedicated service/config validation command; final health adds
  Pulse, StateSummary, Resources, agent, and optional StreamDeck checks.

These are not correctness theatre when a mutation has just happened. They are
the right checks at the right evidence tier. The simplification opportunity is
to retain a clear “trust changed, therefore recheck” boundary while removing
reconstruction of unchanged local plans and avoiding duplicate readiness polls
when the previous successful observation is still authoritative.

The module loop is also a source of operator pain. Adding one module can cause
secret collection, USB discovery, artifact qualification, LXC provisioning,
credential installation, limited Ansible, DNS verification, and then full
Ansible. That is appropriate for a destructive/live deploy, but it is too much
implicit work for a command named `module enable` unless the output gives a
single concise intent summary and a recovery state.

### `verify` and `status`

`verify` is a good evidence collector, but its name and side effects are not
aligned. `internal/cli/verify.go:33-99` loads the site, collects offline or
live checks, writes `verification.json` and `status.json`, and may rebuild the
portal. `status` uses the same health collection but does not write these
artifacts (`internal/cli/status.go:20-70`).

Offline verification calls the canonical load once and then approximately:

* firewall plan twice;
* DNS, Pulse, backup, and storage once each;
* qualified Proxmox evidence/plan three times;
* bastion policy once;
* portal once if configured.

That is 11 without portal, 12 with portal. Managed live verification adds
approximately four more validation-equivalents through the live gateway plan
and ruleset/publication path, yielding 15 or 16.

The evidence-tier model in `internal/status/status.go` is valuable: it
distinguishes local, remote, deployed, journey, and product evidence and
preserves `HOLD`, `NOT TESTED`, and `INCONCLUSIVE`. The problem is calibration
and presentation, not the model. Unknown check names default to local, and
doctor/network-probe output does not consistently follow the binary operator
contract. A simpler UI can still retain the full raw report underneath.

### `doctor`

Doctor is a recovery/audit command rather than a normal health check. It reads
16 revision-bearing artifacts individually, checks Age/SOPS/runtime/platform
ownership, inspects optional AIOps, checks live gateway state, and when live
audits Proxmox guests, node storage, network state, physical binding, and
dedicated storage.

The offline model-plan count is about eight; a managed live run is about 14,
before an optional nested AIOps status call. The expensive part is not only
validation. The command emits a large list of `CURRENT`, `ABSENT`, and
`INCONSISTENT` observations that is useful during recovery but cognitively
heavy for routine use.

The 16 revision checks are especially weak as an audit primitive because each
does a bounded read and substring match. A single generated manifest containing
revision, schema, artifact identity, and content digest could provide a much
clearer consistency check. Security-sensitive files should still be parsed and
validated independently; the manifest should remove only redundant freshness
reads.

### `init`, `preflight`, and `bootstrap`

`init` correctly refuses a non-empty site directory, establishes identity and
PKI, composes the initial site, writes atomic config/secrets, and creates
generated state. However, it prints `Readiness: FAIL` and returns success after
initialization (`internal/cli/init.go:21-53`). That is likely to confuse an
operator and scripts: successful setup with an expected “not ready until
bootstrap” state should have a distinct result, not a failure word with a zero
exit status.

`preflight` is a sensible read-only gate. It checks tools, configured module
readiness, credentials, mode/trunk ambiguity, and optionally live device and
endpoint state. `--record` explicitly requires `--live`, which preserves the
observation/persistence boundary. The offline path is about four validation-
equivalents and the recorded live path about five, plus live probes.

Bootstrap has high ceremony because it is the first trust transition: host-key
enrollment, credentials, optional storage initialization, TLS/API identity,
node matching, physical network analysis, bridge/trunk configuration, artifact
build/qualification, and final persistence. The source-derived local count is
about 31. The artifact builder’s cache ownership, builder identity, capacity,
source archive, bounded transfer, digest rebinding, qualification, and cleanup
checks are valuable. The simplification target is not to skip them; it is to
make one bootstrap transaction expose which steps are trust establishment,
which are artifact work, and which are merely repeated projection rendering.

### Module flows

Module resolution in `internal/modules/registry.go:211-565` validates the
first-party registry, checks configuration schema, resolves dependencies and
capabilities, and produces topological order. This prevents invalid module
graphs and should remain.

`module configure` is secure but auditor-like. It composes current and proposed
state, separately composes a baseline for the diff, prompts for fields and
dependencies, validates USB identity/port, collects declarations, checks
existing secret presence, prompts for missing secrets, confirms, and writes
desired state without deploying. The separation is conceptually clean, but
three full compositions plus per-secret prompting is too much friction for a
personal appliance.

`module enable`/`disable` is less clean: it updates desired configuration and
then immediately runs deploy. The normal path composes the modified state,
loads the old state, and composes again inside deploy. Purge adds exact target
matching, guest audit, and destructive cleanup. The purge proof is valuable;
the coupling of desired-state mutation and live convergence should be made
visibly intentional.

USB binding is a similar UX hotspot. It validates the compiled-in requirement,
observes a physical device, checks identity and port collisions, composes the
site, saves, and immediately deploys. That is excellent protection against
binding the wrong device, but the command should make the full-deploy cost
obvious or offer a desired-only path where that is safe.

### Control-plane mutation commands

These commands generally have the right safety posture, but several recompose
more than necessary:

* DNS add/remove does current composition, proposed composition, saves, then
  reloads/composes again to persist pending deletions. The rollback is worth
  retaining; the third full composition can be folded into the transaction’s
  already validated proposed state if the post-save read is limited to
  persistence integrity.
* DNS record add/remove composes current and proposed state. Optional VMID
  resolution does real live identity/address proof and should remain.
* Firewall rule add composes and validates the resolved site after mutation and
  can perform live guest proof. Firewall rule remove does not compose the
  current state, creating an asymmetry that deserves a negative-path test.
* Storage status has a single plan plus one bounded remote status command.
  Storage initialization’s dedicated profile, bootstrap, explicit confirmation,
  owner checks, and post-action status are appropriate.
* Network trunk attach/detach has the strongest expected mutation pattern:
  observe, confirm, mutate, reread, validate, analyze, save, regenerate, and
  rollback on failed reread/validation. It is slow because it is protecting a
  physical network boundary; do not replace that with local model checks.
* SSH and PKI commands maintain strict host identity, execution configuration,
  private-key handling, revocation metadata, and portal refresh. Those are
  valuable boundaries. The repeated root validation behind rendering can be
  shared.

### Network test

Network test intentionally creates temporary probes, issues short-lived client
credentials, runs gateway/DNS/TCP/Nmap/mTLS/iperf cases, and always attempts
exact-owner cleanup. Its normal local validation-equivalent count is about
five; cleanup-only is two.

The case count grows with DNS servers, platform endpoints, cross-zone pairs,
and mTLS targets. That is real isolation evidence, not merely ceremony, but
the operator output should distinguish:

* `PASS`: the specific path was observed;
* `FAIL`: the path was observed and failed;
* `INCONCLUSIVE`: the path could not establish a reliable result;
* cleanup failure: a separate blocking lifecycle failure.

Mapping every non-pass result to terminal `FAIL` makes the tool feel decisive
but overstates certainty. The report already has the richer state; expose the
same distinction in the normal summary.

## Validation and evidence inventory

### Desired-state and schema checks

`Site.Validate` is a strong canonical gate. It enforces product version and
platform, SSH/bootstrap identity, storage and physical mode, topology, module
ownership, fixed foundation components, DHCP/DNS/firewall declarations,
retained ownership, secret syntax/lifecycle, device access, and volume
semantics. This is the project’s most valuable local correctness layer.

The weakness is placement: consumers use it as a reusable precondition but pay
for a full traversal every time. Split the API conceptually into:

1. a composition boundary that establishes `ValidatedSite`;
2. output-specific checks that validate the thing about to be emitted; and
3. live/destructive checks that re-observe external state.

Do not weaken the checks; stop making pure consumers prove the same root fact
again inside one command.

### Registry and dependency checks

The registry validates ten bounded first-party modules, reserved VMID blocks,
placement, config schema, USB bindings, guest IDs/addresses, dependencies,
capabilities, and topological order. This is valuable because a module is a
compiled-in product feature, not an arbitrary workload. It is also a cheap
place to provide joyful UX: configuration errors can be reported as one
dependency summary rather than discovered through a chain of prompts.

The registry itself is immutable. Validating its static definitions at process
construction or through a cached immutable result would remove repeated work
without weakening user-supplied configuration validation.

### Artifact and supply-chain checks

Artifact evidence is among the least theatrical code in the repository. It
checks evaluator identity, qualified state, definition identity, content
digest, path containment, qualification input hashes, and actual file hashes;
then `ResolveQualifiedArtifacts` binds each guest declaration to that evidence
before mutation. Builder cache ownership and evidence rebinding after transfer
are similarly justified.

The operator pain is mostly latency and vocabulary. Keep the checks, but show a
single artifact readiness result with the artifact ID, digest short form,
qualification age, and the reason for a rebuild. Do not print or expose secret
material while improving that summary.

### Remote identity, readiness, and health

The deployment flow does not confuse a rendered configuration with a working
appliance. It rechecks host identity, gateway interfaces/routes/services,
DNS services/configuration, mTLS journeys, API health, Pulse state, and
optional module health. This is precisely the evidence hierarchy the product
needs.

The main UX problem is that source-level static checks and live checks are
presented as one long gauntlet. The phase report should say, for each phase,
whether it is proving local shape, remote configuration, deployed readiness,
or an authenticated journey. That makes necessary waiting legible and makes
duplicate local work visible during optimization.

### Ansible correctness work

The roles contain 29 source occurrences of `ansible.builtin.assert`, 33
`changed_when`, 7 `failed_when`, 1 `until`, and 1 `retries` occurrence across
the role tree. These are source occurrence counts, not per-deploy execution
counts. Actual execution depends on enabled modules and task inclusion.

Assertions around service state, configuration, versions, identity, and
networking are valuable at the remote boundary. `RunLimited` also validates
the safe inventory identity before limiting execution. `RunWithMutation`
records only a coarse changed count, not a per-resource audit; that is a
reasonable operational summary but should not be sold as a complete audit
trail.

Ansible variable rendering is the largest local repetition source. It should
consume already-derived plans and preserve its own variable/schema/output
checks.

## Operator pain versus prevention

| Area | Likely pain | Prevention value | Judgement |
|---|---|---|---|
| Host-key enrollment and recheck | Long waits and re-arming after identity changes | Prevents wrong-host trust and stale identity | Keep; explain and reuse successful observations where safe. |
| Artifact qualification | Hashing/build delays and opaque failure terms | Prevents unqualified or tampered software | Keep; improve summary and caching. |
| Full local revalidation | Hidden CPU/IO and repeated logs | Little new assurance inside one immutable operation | Simplify aggressively with a validated snapshot. |
| Module configuration | Many prompts, dependency/secret/USB ceremony | Prevents malformed desired state and missing runtime prerequisites | Keep final gate; collapse prompts and compositions. |
| Module enable immediate deploy | One small intent triggers full convergence | Ensures desired state is applied immediately | Make coupling explicit or separate desired change from deploy. |
| USB bind immediate deploy | Physical observation followed by a large operation | Prevents wrong-device binding | Keep identity proof; consider desired-only binding. |
| DNS post-save recomposition | Surprising latency | Detects persistence/derived-state errors | Keep rollback; remove duplicate full composition. |
| Doctor artifact inventory | Noisy routine output | Useful during recovery and drift diagnosis | Keep as recovery mode; provide concise default summary. |
| Verify writes evidence | Unexpected files/portal updates | Produces durable evidence and status | Rename/separate the recording side effect or document it strongly. |
| Network test inconclusive handling | Apparent failures when a path was not proven | Rich report preserves uncertainty | Fix terminal presentation; do not collapse states. |
| Destructive storage/network/purge checks | Confirmation and rereads slow work | Prevents irreversible or topology-breaking mistakes | Keep. |

## Recommended simplification sequence

### Tier 0: low-risk, no model redesign

1. Propagate the ignored `modules.Compose(before)` error in
   `configureChanges`.
2. Fail composition on invalid Gatus endpoint URLs instead of silently
   skipping intents.
3. Make unknown verification check names fail or receive an explicit
   unclassified tier.
4. Preserve `INCONCLUSIVE` in network-test terminal output.
5. Change init’s expected-not-ready result from a printed `FAIL` with success
   exit to a distinct setup/readiness message.
6. Add a compact deploy line for “local model/projection validation” so the
   operator can see its time without reading dozens of repeated plan logs.
7. Consolidate doctor revision checks behind a typed manifest or at least a
   strict equality/structured read rather than `strings.Contains`.
8. Expand the operation-local platform secret cache to cover all secrets used
   by that operation, retaining non-echo input and atomic persistence.

### Tier 1: remove repeated pure work

Introduce a small internal `ValidatedOperation`-style value, or an equivalent
unexported context, with:

* canonical `Site` and revision;
* resolved module graph and declarations;
* DNS/firewall/storage/backup/logging/Pulse/USB/Proxmox/Ansible products;
* qualified artifact bindings;
* operation-local platform secret cache; and
* projection metadata.

Build it once after loading/composing desired state. Provider functions should
continue to validate their own output-specific invariants, but accept the
validated site or derived product instead of re-running the full root gate.
The operation context must not become a generic lifecycle manager: keep it
private to deploy/projection construction and retain public boundary checks for
commands that load independently.

This should reduce projection refresh from about 20 validation-equivalents to
one canonical validation plus output-specific checks, and reduce the typical
deploy’s pure local count by dozens without changing live evidence.

### Tier 2: make routine module UX joyful

* Gather module, dependency, USB, and secret intent into one proposal.
* Reuse existing valid declarations and present only missing choices.
* Show one summary: desired change, required modules, guests, USB binding,
  secrets to supply, artifacts, and estimated deploy scope.
* Ask for one confirmation for the proposal.
* Keep deployment explicit in the final result: either clearly state that
  `module enable` includes deploy, or make desired-state change and deploy
  separate consistently across module and USB commands.
* Keep a concise recovery command when desired state changed but convergence
  failed.

### Do not simplify these boundaries

Do not replace live gateway checks with rendered nftables, replace artifact
qualification with a local checksum alone, adopt unknown guests, remove
host-key proof, skip post-mutation rereads, turn cleanup failure into a warning,
or treat a health endpoint as an authenticated product journey. Those would
make the tool feel faster by weakening the proof it is supposed to provide.

## Measured follow-up: Issue #77

The source review above was intentionally static. The following measurements
are a separate live follow-up on a disposable site with all first-party
optional modules enabled except the intentionally disabled AirVPN and Gatus
modules. They are evidence for the current `0.4.3` branch, not a claim about
every site shape.

The five-run linear warm baseline was 352.012 seconds median and 357.548
seconds nearest-rank p95. The first code-controlled service-only run reached
307.104 seconds, with 146.556 seconds in network convergence and 36.188
seconds in services convergence. That isolates the service-phase scheduling
gain, but it is not the final comparison because the network phase was still
linear.

Commit `bbce54e` applies the same bounded `free` Ansible strategy to the
all-host network/bootstrap pass, only after the managed gateway and both DNS
guests pass runtime readiness. The first combined warm run completed in
251.722 seconds: appliances 54.796 seconds, network 93.213 seconds, services
36.122 seconds, and health 62.062 seconds. That is 100.290 seconds, or 28.5%,
below the linear median and leaves 48.278 seconds inside the five-minute
full-deploy objective. At that point it was only a single-run result; the
matrix below adds comparable warm samples and the associated failure record.

The subsequent warm matrix produced four more passing runs at 248.407,
246.696, 248.099, and 240.083 seconds. Across the five passing runs, the
median is 248.099 seconds and the nearest-rank p95 is 251.722 seconds; the
phase medians are appliances 53.861 seconds, network 92.449 seconds, services
35.448 seconds, and health 62.062 seconds. The p95 is 103.913 seconds, or
29.5%, below the five-run linear median and leaves 48.278 seconds inside the
five-minute objective.

There was one intervening failed attempt at 223.548 seconds. Its strict AIOps
canary returned `EOF`, and its cleanup then failed to revoke temporary root
access on `lab-dns-01` after the Proxmox endpoint briefly became unreachable.
The failure is retained as reliability evidence rather than excluded from the
history. Proxmox recovered, the next native deploy passed the AIOps canary and
removed temporary authority, and commit `b3c8ef5` makes cleanup attempt every
exact guest and host target before returning a combined failure. Therefore the
five timing samples are a preliminary optimized p95, not a claim of
failure-free qualification.

The live gates remained intact on that run: status reported 13/13 checks
healthy, `verify --live` passed, `doctor --live` passed, and the native network
smoke suite passed all 122 cases with cleanup passing. No ownership, trust,
replacement, mutation-scope, or final-health gate was removed. The status,
verify, and doctor checks must use the site-local generated SSH configuration
when inspecting an isolated site directory.

Cold behavior remains a different problem. The isolated cold bootstrap took
1,037.908 seconds and the cold deploy took 1,068.507 seconds. Builder work
dominated: image build 585.790 seconds, qualification 214.299 seconds, and
the returned artifact stream 104.836 seconds. The warm five-minute result must
not be presented as a cold-install result.

The measurements do not support implementing a broad operation-local snapshot
yet: local validation and projection preparation are single-digit
milliseconds in the live report, while remote readiness, appliance work,
Ansible convergence, and authenticated health journeys dominate. The current
highest-value structural changes are therefore the bounded phase scheduling
already implemented, artifact/build-cache and compression measurement, and
avoiding certificate or configuration churn. A snapshot can be revisited if
future instrumentation shows local preparation becoming material.

The 180-second warm aspiration in Issue #77 was not reached: the measured
optimized p95 remains 71.722 seconds above it. Reaching it would require
materially changing the remaining remote critical path—especially network
convergence and health journeys—not removing their proof. That is a separate
optimisation decision with a higher correctness risk. The current five-minute
objective is met across the five passing timing samples, subject to the one
recorded AIOps reliability failure and its recovery.

## Evidence limits

The original review was source-derived and local. The repository test suite
was also run on this branch with task-local Go caches:

```text
go test ./...
PASS
```

That proves the current tests pass locally. The measured follow-up adds the
explicit live evidence described above, but does not prove remote CI,
deployment of a different revision, browser/API journeys outside the exercised
paths, physical USB/storage state beyond the disposable run, or product-level
acceptance for other module sets. Runtime counts will vary with enabled
modules, external endpoints, retained guests, physical mode, AIOps, and retry
paths. The source-derived counts remain a map of repetition, while the timing
claims are limited to the measured disposable runs and their stated
qualification status.
