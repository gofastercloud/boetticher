# Tailscale access

The optional first-party `tailnet-router` module provides the supported
Tailscale subnet-router path. It is default-off and runs as an unprivileged
Debian LXC in the Core-owned TRANSIT zone at `10.10.5.10`.

The module advertises only `10.10.0.0/16`, sets `accept-dns=false`, enables
subnet-route SNAT, and does not enable Internet exit-node behavior. Core owns
the managed-gateway firewall policy; external-gateway mode emits an operator
contract only. Route approval, Tailnet ACLs, registration, subnet access, and
live negative journeys remain operator/live qualification actions. A requested
live check fails with its next action until those gates are executed;
source-only artifacts do not claim live success.
