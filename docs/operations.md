# Operations

The CLI owns the product lifecycle:

```text
init → preflight → bootstrap → provision → converge → verify → doctor
                                      ↘ portal build
```

Use `bootstrap-endpoint` to record the known HOME-side Proxmox address, `preflight --live` to discover and classify physical NICs, `ssh-config` to render operator access, `network trunk` for the guarded physical-trunk transition, and `pki` for client certificates and trust export. `upgrade` remains an explicit compatibility gate until schema and live migration qualification exists.

## Evidence semantics

`boetticher verify` separates generated SSH configuration, network reachability, and authenticated SSH journey evidence. Offline checks can pass before hardware is available; service journeys remain not yet tested. `boetticher doctor` reports each projection as `ABSENT`, `CURRENT`, or `INCONSISTENT` against the current model revision, separately reports physical binding and unmanaged Proxmox guests, and preserves the OPNsense bootstrap gate.

Generated artifacts may be committed to the private site repository. Runtime state, OpenTofu state/plans/caches, bootstrap state, and temporary credentials remain outside Git.

## Portal versus Zabbix

The portal is the human-readable projection of architecture, configuration, runbooks, and the latest platform verification evidence. It is rebuilt after successful platform commands and can be refreshed from non-secret status metadata. It does not poll guests or reproduce graphs. Zabbix owns metrics, dashboards, synthetic checks, certificates, events, alerting, and notifications.
