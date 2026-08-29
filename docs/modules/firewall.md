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
