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

## Qualification-only disposable network probe harness

Use a separate, reusable qualification tool for network-path testing. It must
not become a Boetticher module, desired-state field, supported appliance, or
normal CLI command. This is a test plan only; it is not part of the 0.4 source
workflow and has not been run.

Reserve LXC VMIDs 910-919 exclusively for the harness. This range is outside
the Boetticher platform, module, and user ownership ranges. Before every run,
the tool must verify that each selected ID is absent or bears the exact
qualification-harness identity. It must refuse wrong-kind, wrong-name,
wrong-tag, or ambiguous occupants and must never allocate around a collision.

Create one unprivileged, non-nested LXC per exercised zone, with one vNIC and
an exact VLAN tag. Use DHCP for TRUSTED and SANDBOX, the declared reservation
flow for SERVERS, and fixed addresses for TRANSIT, INFRA, and MGMT. The test
address pool must be checked against the current model and reservations before
creation; example addresses are not a release contract. Do not infer DHCP
success from generated configuration: record the guest lease and the gateway's
read-only Kea observation separately.

Build the probe image from the pinned Debian base with a recorded content
digest, package manifest, SBOM, and bounded vulnerability result. The
qualification-only image may contain `iproute2`, `iputils-ping`, `dnsutils`,
`iperf3`, `netcat-openbsd`, `nmap`, `curl`, `jq`, and bounded packet-capture
tools. It must not be added to the supported 0.4 artifact catalog. Keep packet
capture on the gateway/router to bounded `tcpdump` or `tshark` sessions and
move pcaps to the controller for offline Wireshark analysis; do not install a
GUI Wireshark workload on the firewall.

The harness should run bounded, machine-readable cases for:

1. DHCP lease allocation, renewal, expiry, and the SERVERS reservation path;
   static-only zones report the expected non-applicable result.
2. DDNS forward A and PTR publication, secondary visibility, and removal or
   expiry where practical.
3. Gateway reachability, permitted egress, and forbidden inter-zone paths.
4. Firewall allow/deny cases using declared netcat targets and a tightly
   allow-listed, fixed-port `nmap` scan; collect before/after telemetry
   counters.
5. Network performance using fixed-duration `iperf3` TCP tests and, where
   useful, bounded UDP rate/loss tests, plus RTT and MTU evidence. Performance
   is diagnostic evidence, not an automatic platform-health PASS.
6. Optional bounded packet captures around DHCP, DNS/DDNS, and denied flows.

Each result records the harness version, model revision, VMID, guest identity,
zone/address, exact command or case, start/end time, observation, evidence
tier, and bounded failure output. `PASS` requires current authenticated guest
and gateway observations; missing or ambiguous evidence is `HOLD` or
`INCONCLUSIVE`, never a generated-configuration PASS.

Teardown runs even after a failed case. Stop and destroy only exact
harness-owned guests, verify their absence through the Proxmox API, remove
temporary snippets and host-key state, and retain hashed evidence separately.
An interrupted run must resume with exact-owner cleanup or return `HOLD`; it
must never use a broad purge. Physical trunk tests remain gated behind the
virtual and DHCP/DDNS cases.

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
