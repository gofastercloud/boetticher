# Firewall and gateway

`firewall` is a default-on module in managed-gateway mode. It provides the
Debian gateway, routing, NAT, DHCP/DDNS, NTP, inter-zone policy, and a bounded
read-only telemetry API for Pulse. Core owns the platform policy; user
workloads remain outside the platform model.

The normal operator choice is gateway mode during `boetticher init`:

- managed mode creates and maintains the fixed gateway appliance; or
- external-firewall mode publishes the VLAN, address, DHCP, NAT, and policy
  contract for an operator-owned appliance.

Use `boetticher firewall status`, `boetticher firewall diff`, and
`boetticher doctor --live` to inspect a managed gateway. User-workload rule
intent can be recorded with `boetticher firewall rule add` or `remove`; those
commands change desired state only. Apply the result with `boetticher deploy`.

The gateway's telemetry endpoint is an internal consumer boundary, not a
general administration API. Its current live reachability, firewall policy,
and external-appliance behavior must be checked on the deployed network.

The built-in policy permits HTTPS to the fixed Pulse and Portal endpoints
(`lab-monitor-01`, `10.10.10.20`; `lab-portal-01`, `10.10.10.30`) from the
TRANSIT, SERVERS, and TRUSTED zones. Pulse and Portal still require trusted
client certificates at their TLS boundaries, and these network rules do not
grant access to other INFRA services.

User-workload rules remain separate from that built-in policy and are blocked
from Core destinations except for one bounded dashboard path: a reserved
SERVERS `/32` may be allowed to Pulse on TCP/443. The model requires the source
address to match an existing SERVERS DHCP reservation and rejects zone-wide
sources, other Core destinations, and other ports. For example:

```text
boetticher firewall rule add --source 10.10.20.50/32 --destination 10.10.10.20/32 --protocol tcp --ports 443 --id ufr-lab-display-pulse --confirm --site ./my-boetticher
```

This records desired state only; apply it with `boetticher deploy` and verify
the live Pulse path from the reserved client.
