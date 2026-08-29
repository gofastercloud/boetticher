# Operations

The CLI owns the product lifecycle:

```text
init → preflight → bootstrap → deploy → verify → doctor
                                      ↘ portal build
```

Use `bootstrap-endpoint` to record the known HOME-side Proxmox address, `preflight --live` to discover and classify physical NICs, `ssh-config` to render the controller's internal deployment transport, `network trunk` for the guarded physical-trunk transition, and `pki` for client certificates and trust export. Routine administration of Core-managed appliances uses the Boetticher CLI, native product UI/API where appropriate, and generated portal/status surfaces; explicit Proxmox console/exec is the break-glass recovery path. The external firewall remains operator-managed through its own interface. The dedicated-data-disk layout is initialized as part of guarded `bootstrap`; `doctor --live` reports its Proxmox registrations and capacity. `upgrade` remains an explicit compatibility gate until schema and live migration qualification exists.

Managed `init`, `preflight`, and `bootstrap --dry-run` display the persisted
`wan0` MAC. Reserve it in the existing upstream DHCP service before deploying.
When DNS publication is configured, `deploy` performs a safe gateway/DNS
readiness pass, observes the current upstream address/prefix/default gateway,
and then activates the bounded DNAT policy. `verify --live`, `doctor --live`,
and `firewall status --live` report that effective observation; no live lease
is promoted into canonical desired state.

## How checks are reported

`boetticher verify` keeps generated SSH configuration, network reachability,
and a real authenticated SSH journey as separate checks. Local checks can pass
before a host is available; service journeys still need to be tried for real.
`boetticher doctor` reports each projection as `ABSENT`, `CURRENT`, or
`INCONSISTENT` against the current model revision, and separately reports
physical binding and unmanaged Proxmox guests.

Appliance binaries, scan roots, build caches, and qualification runtime state
are ignored in the private site repository. Keep those files in the bounded
controller artifact cache or regenerate them through the hosted builder. The
portable recovery set remains the site configuration, encrypted secrets,
recovery authority, and non-secret desired-state projections.

## Deployment privilege

`labadmin` is an unprivileged durable SSH identity on Proxmox and appliances,
with only fixed read-only inspection helpers on the managed firewall. The
scoped Proxmox API token performs ordinary lifecycle operations. A
successful bootstrap supplies temporary root SSH access for deployment;
Ansible connects as root and does not use `become`. Convergence removes the
temporary guest keys and Proxmox host root allowance. A failed deployment
retains that access for retry, while cleanup failure is a hold. Operator root
access remains the break-glass bootstrap and recovery path.

## Portal versus monitoring

The portal is the human-readable projection of architecture, configuration,
runbooks, and the latest platform verification results. It is rebuilt after
successful platform commands and can be refreshed from non-secret status
metadata. It does not poll guests or reproduce graphs. Pulse owns metrics,
dashboards, synthetic checks, certificates, events, alerting, and
notifications.

## Managed firewall telemetry

The managed firewall publishes a bounded, read-only evidence API for Pulse
and future internal AIOps consumers at `http://10.10.10.1:9765`:

- `GET /healthz` reports collector health and sample age.
- `GET /api/v1/summary` reports fixed 5-minute, 1-hour, and 24-hour deltas,
  collector health, the last structural change, and active deny/drop rules.
- `GET /api/v1/rules` and `GET /api/v1/rules/{id}` expose bounded rule metadata
  and current counters.
- `GET /api/v1/rules/{id}/activity?window=...` accepts only `1m`, `5m`, `15m`,
  `1h`, `6h`, `24h`, or `7d`, with at most 256 samples.
- `GET /api/v1/events?since=...` is limited to the last seven days and 200
  events.

The service accepts only GET requests and only from `10.10.10.20`. It ignores
non-Boetticher rules, treats counter decreases as a new epoch with zero delta,
and records a deterministic owned-ruleset fingerprint change. The SQLite
database is persistent firewall state and raw samples are retained for seven
days.
