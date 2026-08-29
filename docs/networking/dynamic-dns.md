# Dynamic DNS

PowerDNS Authoritative on `lab-dns-01` is the primary update target and
`lab-dns-02` is the secondary. The qualified v0.4 target is PowerDNS
Authoritative 4.9.17. Blocky forwards the static and dynamic zones to the
local/redundant authoritative service.

Managed mode uses Kea D2 on `lab-fw-01` to send authenticated RFC2136 updates.
External mode can provide the same feature only if the operator's DHCP service
implements the published RFC2136/TSIG contract. Without that integration,
static platform DNS still works and DHCP still succeeds; only lease-derived
names are unavailable.

Dynamic child zones are fixed to `servers.lab.home.arpa`,
`trusted.lab.home.arpa`, and `sandbox.lab.home.arpa`, with the corresponding
reverse zones. SERVERS is reservation-only: only explicitly declared MAC
identities receive addresses, while Kea D2 may publish their lease-derived
names. TRUSTED and SANDBOX retain their existing dynamic/reservation behavior.
TRANSIT, INFRA, and MGMT are static-only and do not originate DHCP or DDNS
updates. Platform and module names remain in the static `lab.home.arpa` zone
and cannot be claimed by DHCP clients.

User A and CNAME records are present-only desired state and use `value`; user
records cannot replace Core-, module-, or DHCP/DDNS-owned RRsets. The
DHCP/DDNS-owned child namespaces are reserved for lease-derived records, but a
user alias in the static zone may point to a lease-derived name, for example
`app.lab.home.arpa CNAME app-01.servers.lab.home.arpa`. Exact user deletions
are controller-local pending reconciliation state and are removed only after
a successful deploy. Invalid names are rejected, conflicts follow the
deterministic reject-new-active-lease policy, and DDNS failure does not deny a
lease.
