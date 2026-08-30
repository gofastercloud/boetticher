# First live-install checklist

This is the short list for the first real deployment on a disposable,
recoverable Proxmox host. The repository is pre-alpha; local tests do not prove
these journeys.

## Managed mode

1. Install the supported Proxmox release and run the README quickstart exactly.
2. Run `preflight --live`, then `bootstrap` through the hosted-builder
   qualification stop. Confirm the builder is temporary and absent after
   artifact retrieval.
3. Run the first virtual-only `deploy --dry-run`, inspect the qualified
   artifacts and firewall-first order, then apply `deploy`. Supply
   `--confirm` only when the plan identifies a supported destructive action
   that explicitly requires confirmation.
4. Confirm the supported operator boundary: use the Boetticher CLI and native
   product interfaces for routine administration; reserve explicit Proxmox
   console/exec for break-glass recovery. Internal deployment SSH remains an
   implementation transport and is not an operator administration gate.
5. Confirm VM 100 has WAN plus six tagged zone vNICs and that it is the
   qualified boetticher firewall appliance.
6. Prove Kea leases, PowerDNS DDNS, secondary replication, and both DNS/NTP
   paths.
7. Prove Pulse Proxmox API inventory, tagged Proxmox-host agent hardware
   telemetry, alerts, availability checks, and backup freshness.
8. Prove portal TLS/mTLS and reject an unauthenticated client.
9. Exercise the positive and negative firewall journeys, especially SANDBOX.
10. On `lab-monitor-01`, health-check `http://10.10.10.1:9765/healthz` and
    confirm an unauthorized internal source cannot connect.
11. Generate allowed traffic and confirm the expected `boetticher:allow:<id>`
    counter and bounded API activity increase; generate denied traffic and do
    the same for `boetticher:deny:<id>` or `boetticher:drop:<id>`.
12. Reload or reset the firewall, confirm no negative deltas are reported, and
    make a structural ruleset change that produces a ruleset-change event.
13. Reboot the firewall and confirm the telemetry database retains its prior
    rule metadata, epochs, samples within retention, and events.
14. Verify the telemetry process is non-root and cannot mutate nftables; this
    service must not provide SSH, shell, database, or WAN access.
15. Attach a clean second NIC with `boetticher network trunk attach IFACE --confirm` and
   prove physical VLAN access through a managed switch.
16. Reboot, rerun critical journeys, rerun deploy, and require no unexpected
   changes.

## Disposable network probe harness

`boetticher network test` is an advanced supported diagnostic command for
network-path testing. It is not a module or desired-state component. Bootstrap
qualifies its small Debian LXC image; each invocation creates temporary probes,
runs bounded checks, records private evidence, and removes the probes.

Reserve LXC VMIDs 910-919 exclusively for the harness. This range is outside
the Boetticher platform, module, and user ownership ranges. Before every run,
the tool must verify that each selected ID is absent or bears the exact
qualification-harness identity. It must refuse wrong-kind, wrong-name,
wrong-tag, or ambiguous occupants and must never allocate around a collision.

Create one unprivileged, non-nested LXC per exercised zone, with one vNIC and
an exact VLAN tag. Use DHCP for TRUSTED and SANDBOX and collision-checked
temporary static addresses for TRANSIT, INFRA, SERVERS, and MGMT. The command
does not add reservations or firewall rules. SERVERS reservation coverage is
`NOT TESTED` unless a matching reservation already exists.

The qualified probe image contains `iproute2`, `iputils-ping`, `arping`,
`dnsutils`, `iperf3`, `netcat-openbsd`, `nmap`, `curl`, `openssl`, `chrony`,
`jq`, and bounded `tcpdump`. Its host-side executor is a root-owned,
forced-command SSH boundary that accepts only the probe protocol; it cannot
run arbitrary commands or change firewall state.

The current harness runs bounded, machine-readable cases for:

1. Gateway reachability and DNS A lookups against each resolver declared for
   the selected zone.
2. Modeled allow/deny endpoint checks using `netcat` and a tightly bounded,
   fixed-port `nmap` scan.
3. mTLS negative and positive handshakes against every enabled modeled mTLS
   HTTPS endpoint, including Pulse where enabled.
4. Fixed-duration `iperf3` TCP tests and bounded UDP tests only over already-
   modeled allowed paths. Performance is diagnostic evidence, not an
   automatic platform-health PASS.
5. Optional bounded packet captures from the probe's own interface.

DHCP lease, DDNS, and firewall-counter assertions remain outside this first
   implementation; their results are not inferred from generated
   configuration.

Each result records the harness version, model revision, VMID, guest identity,
zone/address, exact command or case, start/end time, observation, evidence
tier, and bounded failure output. `PASS` requires current authenticated guest
and gateway observations; missing or ambiguous evidence is `HOLD` or
`INCONCLUSIVE`, never a generated-configuration PASS.

Teardown runs even after a failed case. Stop and destroy only exact
harness-owned guests and verify their absence through the Proxmox API. An
interrupted run resumes exact-owner cleanup with `--cleanup-only` or returns
`HOLD`; it never uses a broad purge. Evidence is written below the private
runtime directory, and physical trunk tests remain gated behind the virtual
and DHCP/DDNS cases.

## External mode

1. Create a fresh site with `boetticher init --external-firewall`.
2. Confirm preflight refuses virtual-only mode and requires a distinct trunk.
3. Configure the operator-owned appliance from the generated contract.
4. Prove gateway addresses, DHCP, DNS/NTP, positive egress, and SANDBOX
   isolation from suitable managed endpoints.
5. If desired, prove external RFC2136/TSIG DDNS and document when it is absent.

For every item record the exact command, model revision, and relevant current
configuration. A successful local renderer is not proof of a live journey.
Use plain labels such as PASS, FAIL, NOT TESTED, or HOLD when writing the
results.
