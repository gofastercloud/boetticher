# DHCP-driven dynamic DNS

Dynamic DNS is a V1 platform capability. A normal user VM/LXC does not need a registration command:

```text
attach to a zone VLAN
→ request DHCP with a hostname or DHCP option 81 FQDN
→ receive address, gateway, DNS, and NTP
→ resolve as hostname.<zone>.lab.home.arpa
```

## Ownership and data flow

```text
Kea on OPNsense
  DHCP lease authority and D2 lifecycle events
        |
        | authenticated RFC2136 / TSIG
        v
PowerDNS Authoritative on lab-dns-01
        |
        | AXFR/IXFR replication
        v
PowerDNS Authoritative on lab-dns-02
        |
        v
AdGuard Home on both DNS nodes
  client-facing TCP/UDP 53 and conditional forwarding
```

PowerDNS Authoritative is the pinned V1 implementation (`4.9.16` in the model). It listens on the internal authoritative port `5353`; AdGuard owns client-facing TCP/UDP 53 and forwards the boetticher zones to the local PowerDNS process. AdGuard Home and Unbound are not RFC2136 update targets. The authoritative service owns dynamic child zones; AdGuard remains the normal client-facing filtering/upstream resolver.

Convergence enables OPNsense's Kea D2 agent through the global `/api/kea/ddns/set` model and then applies the per-subnet forward/reverse zone and TSIG settings. Kea sends authenticated updates to `10.10.20.10:5353`; the authoritative update listener is reachable only from the intended OPNsense path, not from client VLANs.

The static platform zone is `lab.home.arpa`. DHCP-derived child zones are:

```text
trusted.lab.home.arpa
servers.lab.home.arpa
sandbox.lab.home.arpa
mgmt.lab.home.arpa
```

Reverse zones are generated for the fixed `/24` networks. Platform names and aliases such as `lab-dns-01.lab.home.arpa` and `monitor.lab.home.arpa` are model-generated static records and cannot be claimed by DHCP clients.

## Lifecycle contract

- Valid DHCP hostnames and option 81 FQDNs are qualified by the lease subnet.
- Lease grant/change creates or updates A and PTR records.
- Release, expiry, and replacement remove or update stale A/PTR records according to the Kea D2 lifecycle.
- Renewal can self-heal missing records where the qualified client behavior supports it.
- Invalid, empty, or unsafe names create no record.
- Duplicate active identities follow the deterministic reject-new-active-lease policy; an active record is never silently replaced.
- DDNS failure does not prevent an otherwise valid DHCP lease.
- The update listener accepts only the intended Kea D2/PowerDNS path and is not exposed to client VLANs.

The TSIG secret is generated at initialization, encrypted in SOPS, and streamed to runtime convergence from controller memory. It is not present in generated JSON, the portal, Git, command arguments, persistent environment, or logs.

TRUSTED, SERVERS, and MGMT receive both AdGuard addresses. SANDBOX receives only the OPNsense interface for DNS and does not gain broad `lab.home.arpa` visibility merely because its lease names are registered. Use a reservation or static application record for a service name that must not follow a DHCP lease.

The exact PowerDNS package/backend/replication fixture and OPNsense 26.7.x D2 API payloads remain live qualification gates. The deterministic model, API payload contract, secret boundary, and negative tests are implemented locally; no live DDNS success is claimed without a fresh-host test.
