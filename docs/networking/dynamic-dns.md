# Dynamic DNS

PowerDNS Authoritative on `lab-dns-01` is the primary update target and
`lab-dns-02` is the secondary. The qualified v0.3 target is PowerDNS
Authoritative 4.9.17. The selected recursive provider forwards the static and
dynamic zones to the local/redundant authoritative service.

Managed mode uses Kea D2 on `lab-fw-01` to send authenticated RFC2136 updates.
External mode can provide the same feature only if the operator's DHCP service
implements the published RFC2136/TSIG contract. Without that integration,
static platform DNS still works and DHCP still succeeds; only lease-derived
names are unavailable.

Dynamic child zones are fixed: `trusted.lab.home.arpa`,
`servers.lab.home.arpa`, `sandbox.lab.home.arpa`, and `mgmt.lab.home.arpa`, with
the corresponding reverse zones. Platform names remain in the static
`lab.home.arpa` zone and cannot be claimed by DHCP clients. Invalid names are
ignored, conflicts follow the deterministic reject-new-active-lease policy,
and DDNS failure does not deny a lease.
