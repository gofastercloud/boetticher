# T580 greenfield qualification

This is the remaining live-work checklist for the first real boetticher
qualification. It assumes the T580 can be wiped and recovered. Use a fresh
controller checkout, the exact qualified OPNsense patch in `site.yml`, and the
README commands exactly as written.

## Result language

- **PASS**: the stated command or journey behaved as described and the result
  was recorded from the current host.
- **FAIL**: the expected behavior was exercised and did not hold. Keep the
  output and fix the implementation before repeating.
- **HOLD**: the step cannot be safely exercised yet, is ambiguous, or left an
  uncertain recovery state. Do not guess or continue with destructive changes.
- **NOT TESTED**: the step was not reached or the required hardware/service was
  unavailable.

## Qualification sequence

1. **Fresh Proxmox** — wipe/reinstall the qualified Proxmox release, set the
   node name to `lab-proxmox-01`, and connect it to the existing HOME network.
   PASS means the initial upstream DHCP address is known and reachable.
2. **Controller setup** — run `boetticher init`, secure an independent copy of
   the Age identity, record the address with
   `boetticher bootstrap-endpoint set ADDRESS`, then run `boetticher preflight`.
   PASS means required tools and versions pass and physical discovery reports
   either `virtual-only` or an unambiguous safe trunk proposal.
3. **One-NIC path** — with only the HOME NIC connected, run the README
   quickstart through `boetticher bootstrap` and confirm `vmbr0` retains the
   upstream path while VLAN-aware `vmbr1` has no physical member. PASS means
   the Proxmox bastion still reaches the internal guests.
4. **Proxmox bastion** — generate/install SSH configuration and exercise
   `ssh proxmox`, `ssh dns01`, `ssh monitor`, and `ssh portal`. PASS means the
   internal journeys use `ProxyJump lab-bastion`, fixed IPs, canonical
   `HostKeyAlias`, and normal host-key verification.
5. **OPNsense bootstrap** — complete the unattended firewall VM installation,
   WAN/internal interface assignment, MGMT reachability, scoped identities,
   direct SOPS credential handoff, Kea, firewall, NAT, and temporary privilege
   removal. PASS means this completes from a wiped environment without manual
   OPNsense surgery.
6. **Kea, DNS/DDNS, and NTP** — obtain leases in TRUSTED, SERVERS, SANDBOX,
   and MGMT; verify zone-qualified A/PTR records, release/replacement cleanup,
   PowerDNS secondary replication, AdGuard resolution, Chrony synchronization,
   and SANDBOX’s OPNsense DNS/NTP boundary. PASS means a DDNS failure does not
   prevent a valid DHCP lease.
7. **Zabbix** — open the mTLS-protected frontend with a valid client
   certificate, reject absent and invalid certificates, confirm the platform
   hosts/checks/dashboards are present, and add a synthetic user-owned Zabbix
   object. PASS means boetticher convergence leaves that object alone.
8. **Portal mTLS** — open `https://portal.lab.home.arpa` with a valid client
   certificate and confirm absent/untrusted certificates are rejected. PASS
   means the portal has no CA key, SOPS identity, or control-plane credential.
9. **Negative firewall paths** — from SANDBOX verify TRUSTED, SERVERS, and MGMT
   are denied while Internet, DHCP, DNS, and NTP work. Verify the intended
   TRUSTED, SERVERS, and MGMT administration paths separately.
10. **Physical trunk** — connect the ASIX interface and managed switch, run
    `boetticher network trunk attach IFACE --confirm`, then verify the trunk,
    VLAN tags, physical client paths, and physical SANDBOX isolation mechanism.
    A disconnected clean NIC is valid before the switch is attached.
11. **Reboot** — reboot Proxmox and the platform guests. Repeat bastion, DNS,
    NTP, Zabbix, portal, and negative firewall journeys.
12. **Idempotence** — run `boetticher converge` again and require no unexpected
    changes. Unknown user VMs must remain untouched and informational.
13. **Recovery** — test platform guest backup restore, SOPS/Age recovery, and
    the recorded HOME bootstrap endpoint. Same-disk backup success does not
    prove disaster recovery.
14. **Repeat** — wipe the T580 and repeat the greenfield sequence. The V1
    live qualification is complete only after two clean runs.

Keep the completed checklist with the tested revisions, controller version,
Proxmox/OPNsense versions, and relevant command output. Do not put secrets,
private keys, API responses containing credentials, or client private keys in
the record.
