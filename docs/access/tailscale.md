# Tailscale access

The optional first-party `tailnet-router` module provides the supported
Tailscale subnet-router path. It is default-off and runs as an unprivileged
Debian LXC in the Core-owned TRANSIT zone at `10.10.5.10`.

The module advertises `10.10.0.0/16`, sets `accept-dns=false`, and enables
subnet-route SNAT. Exit-node advertising is opt-in with
`modules.tailnet-router.exit_node: true`; the default is subnet-routing only.
When enabled, Core permits and NATs only the router guest's
`10.10.5.10/32` egress to WAN. The option does not broaden TRANSIT access to
internal zones. In external-gateway mode, the generated contract tells the
operator to provide the equivalent allow and NAT; boetticher does not enforce
it.

Exit-node routing alone does not configure the Tailscale DNS control plane.
To use Blocky filtering for mobile hosts, the Tailnet DNS policy must direct
client DNS to the Blocky service and the clients must use that policy while
the exit node is selected.

Core owns the managed-gateway firewall policy. Route approval, exit-node
selection, Tailnet ACLs, registration, subnet access, DNS filtering, and live
negative journeys remain operator/live qualification actions and are
`NOT TESTED` by this source-only tranche.
