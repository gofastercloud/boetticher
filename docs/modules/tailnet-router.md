# tailnet-router module

`tailnet-router` is an optional, default-off first-party appliance. It is an
unprivileged Debian LXC at `10.10.5.10` in the Core-owned TRANSIT zone and
advertises the service route `10.10.0.0/16` to the Tailnet.

Subnet routing is the default. Set `modules.tailnet-router.exit_node: true`
to opt into Tailscale Internet exit-node advertising. The opt-in adds an exact
managed-gateway allow and source NAT for `10.10.5.10` to WAN; it does not grant
the TRANSIT zone general Internet access or change the internal destination
allowlist. The module continues to advertise the service route
`10.10.0.0/16`; the exit-node capability is separate from that route.

Its Tailscale runtime uses `accept-dns=false`, enables IPv4 forwarding for
routing, retains `/var/lib/tailscale` across immutable rootfs replacement, and
receives the initial operator auth credential through the ephemeral
systemd-credential path. Existing retained state is reconciled without
re-registering on each boot.

Core composes the module's network intent. In managed gateway mode, only the
declared LiteLLM, portal, monitoring, DNS/NTP, logging, and Tailscale
control-plane flows are allowed; the TRANSIT baseline denies other internal
and Internet destinations. External gateway mode emits the equivalent
operator contract and performs no firewall or Tailnet administration.

The appliance has no embedded auth key, site configuration, host SSH keys, or
node identity. Tailscale registration, route approval, exit-node selection,
subnet access, and live disable/re-enable or purge remain `NOT TESTED` until a
separately authorized qualification.
