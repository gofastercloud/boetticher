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

## Reading a deploy result

Deploy works through nine high-level phases. It prints a phase when it starts
and `PASS` when that phase finishes; if a phase fails, later phases are simply
not run. There is no pretend percentage to watch.

The final summary is the useful bit:

```text
Deployment: FAIL
Failed phase: Run live health gates
Infrastructure changed: YES
Temporary authority removed: YES
Retry: YES — rerunning deploy is safe; already-converged resources are retained.
Next action: Run boetticher doctor --live, correct the reported failure, then run boetticher deploy --site ./my-boetticher.
```

On success, the summary says `Deployment: PASS`. On failure, follow the one
`Next action` it prints. If it says cleanup failed, use the recovery guide
before retrying.

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
