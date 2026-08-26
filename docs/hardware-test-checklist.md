# First live-install checklist

This is the short list for the first real deployment on a disposable,
recoverable Proxmox host. The repository is pre-alpha; local tests do not prove
these journeys.

## Managed mode

1. Install the supported Proxmox release and run the README quickstart exactly.
2. Run the one-NIC path and confirm `vmbr1` is healthy in virtual-only mode.
3. Prove `ssh firewall`, `ssh dns01`, `ssh monitor`, and `ssh portal` through
   the Proxmox bastion.
4. Complete managed Debian gateway creation and confirm VM 100 has WAN plus
   four tagged zone vNICs.
5. Prove Kea leases, PowerDNS DDNS, secondary replication, and both DNS/NTP
   paths.
6. Prove Zabbix Agent 2, platform objects, dashboards, and backup freshness.
7. Prove portal TLS/mTLS and reject an unauthenticated client.
8. Exercise the positive and negative firewall journeys, especially SANDBOX.
9. Attach a clean second NIC with `boetticher network trunk attach IFACE` and
   prove physical VLAN access through a managed switch.
10. Reboot, rerun critical journeys, rerun deploy, and require no unexpected
    changes.

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
