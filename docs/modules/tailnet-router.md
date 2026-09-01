# Tailnet Router

`tailnet-router` is an optional, default-off first-party appliance. It is an
unprivileged Debian LXC at `10.10.5.10` in the Core-owned TRANSIT zone and
advertises the service route `10.10.0.0/16` to the Tailnet.

The module does not provide Internet exit-node behavior. Its Tailscale runtime
uses `accept-dns=false`, retains `/var/lib/tailscale` across immutable rootfs
replacement, and receives the initial operator auth credential through the
ephemeral systemd-credential path. Existing retained state is reused without
re-registering on each boot.

Core composes the module's network intent. In managed gateway mode, only the
declared Bifrost, portal, monitoring, DNS/NTP, logging, and Tailscale
control-plane flows are allowed; the TRANSIT baseline denies other internal
and Internet destinations. DNS and NTP intents target both managed DNS
endpoints (dns01 and dns02). Tailscale coordination uses TCP/443 to the
control-plane endpoint and the current `derpN-all.tailscale.com` region
endpoints, resolved when the managed firewall policy is rendered. External
gateway mode emits the equivalent operator contract and performs no firewall
or Tailnet administration.

The appliance has no embedded auth key, site configuration, host SSH keys, or
node identity. Configure it with `boetticher module configure tailnet-router`
and provide the declared `tailscale_auth_key` through the secret prompt or
stdin. Disable retains owned state; purge requires the normal explicit
ownership and confirmation checks.

Tailscale registration, route approval, subnet access, and live lifecycle
behavior require a separate operator-approved verification. Route approval and
Tailnet ACLs remain the operator's responsibility in the Tailnet control plane.
