# Normal operations

After the first installation, most work follows this small loop:

```text
change configuration → deploy → status
```

Use [installation](installation.md) for the first host setup. `deploy` is the
normal command that applies the platform; `status` is the first place to look
when something needs attention.

## Everyday commands

```text
boetticher deploy --site ./my-boetticher --dry-run
boetticher deploy --site ./my-boetticher
boetticher status --site ./my-boetticher --live
boetticher doctor --site ./my-boetticher --live
```

Use `boetticher module configure NAME` to change an optional module, then run
`deploy` separately. Use `boetticher logs` for a bounded view of central
logs. The [module guide](modules/architecture.md) explains what each built-in
capability does and what it keeps.

`module configure` changes local configuration only. Confirmed `module enable`
and `module disable` operations apply their change immediately; use
`--dry-run` first when you want to inspect the plan.

Optional modules stay off until you enable them. The StreamDeck display also
needs a stable physical USB binding; see the [StreamDeck guide](modules/streamdeck.md)
for the short setup path.

`update` changes compatible local configuration; it does not deploy. `upgrade`
is an advanced command that is not available for normal release updates.

## Experimental TUI

`boetticher tui --site ./my-boetticher` opens a small terminal dashboard with
live status, a command list, and a place to run an existing command. It is
experimental: expect rough edges, and use the regular CLI when you need a
repeatable automation or recovery path. The TUI does not create a new
permission model; commands still keep their normal confirmation gates and
secret-handling rules.

Use `--offline` for a local view when the site has not been deployed or live
refresh is not useful. Offline data is only a local projection, so use
`boetticher status --site ./my-boetticher --live` for the supported live check.

## Checking network paths

`boetticher network test --site ./my-boetticher` is an advanced live diagnostic,
not a module and not part of deploy desired state. It creates exact-owned,
unprivileged LXC probes in the reserved 910–919 range, runs bounded
reachability, DNS, policy, mTLS, and performance checks, and attempts cleanup
after every run. It never changes firewall policy.

Keep the first run broad when you are learning the site, or narrow it with
`--zones TRUSTED,SANDBOX`. Add `--capture` for a bounded probe-local capture;
use `--json` when another tool needs the private report. `--cleanup-only` is
the explicit recovery path for stale probes that are still exactly owned by
Boetticher. If cleanup cannot prove ownership or removal, the command fails;
do not work around that safety check with a broad VMID purge.

The experimental TUI includes `network test` in its command list. Use the
direct CLI when you need zones, captures, JSON, or cleanup-only.

## Reading a deploy result

Deploy works through nine high-level phases. It prints a phase when it starts
and `PASS` with its elapsed time when that phase finishes; if a phase fails,
later phases are simply not run. There is no pretend percentage to watch.

Bootstrap uses the same shape. Longer operations also print bounded timing
lines for expensive work such as artifact qualification and Ansible
reconciliation. These are there to make a slow run legible, not to turn the
terminal into a task-by-task log.

At the end of a run, Boetticher prints a private timing-report path. Bootstrap
writes a timestamped JSON report below `bootstrap/` in the site's private
runtime directory. Deploy writes a timestamped JSON report below `deploy/`.
The reports contain
phase and suboperation start times, finish times, and durations, along with
the coarse deployment result and mutation summary. Each suboperation has a
phase, kind, and target, and each report includes the operation, platform
version, and model revision so runs can be compared sensibly. They do not
contain secret values or the full failure text. Keep the files private; they
are useful when comparing a slow run or sharing a small diagnostic bundle with
a maintainer.

Timing is best-effort observability. If the controller cannot write the report,
the operation still succeeds or fails on its own merits and the summary says
`Timing report: unavailable (...)`. A missing timing file is not a reason to
rerun a healthy deployment.

The final summary is the useful bit:

```text
Deployment: FAIL
Failed phase: Run live health gates
Infrastructure changed: YES
Temporary authority removed: YES
Retry: YES — rerunning deploy is safe; already-converged resources are retained.
Next action: Run boetticher doctor --live, correct the reported failure, then run boetticher deploy --site ./my-boetticher.
Timing report: .../runtime/.../deploy/deploy-20260830T120000.000000000Z.json
```

On success, the summary says `Deployment: PASS`. On failure, follow the one
`Next action` it prints. If it says cleanup failed, use the recovery guide
before retrying. The same rules apply to bootstrap: its final result is based
on bootstrap work and temporary-authority cleanup, never on whether timing
could be saved.

## Backups, recovery, and networking

Read [backup ownership](storage/backup-ownership.md) before relying on the
platform backup job, and keep an independent copy of the site repository,
Age identity, and important data. The [recovery guide](recovery/recovery.md)
is the starting point after a failed appliance, lost DNS, or storage problem.

Managed installations are virtual-only by default. Use the
[physical-trunk guide](networking/physical-trunk.md) only when a real trunk is
required; physical changes are guarded because they can interrupt management.
In external-firewall mode, routing, DHCP, NAT, and the network boundary stay
with the operator's appliance.

## Detailed diagnostics

`status` and `verify` use the same current health checks; `verify` additionally
refreshes generated verification and portal artifacts. Add `--live` for the
bounded managed-gateway checks or `--ssh-journey` for the explicit bastion
journey. Checks requiring separate operator, recovery, or product-acceptance
evidence are intentionally omitted. `doctor` remains the deeper diagnostic
command and uses `CURRENT`, `ABSENT`, and `INCONSISTENT` to explain
projections against the current model revision.
Use `doctor` when something needs a next action. A local `PASS` covers local
state only; it does not prove the host or an authenticated journey is working.

For detailed firewall telemetry, appliance privilege, and portal boundaries,
see [the architecture guide](architecture.md), [the security model](security-model.md),
and the relevant advanced module page.
