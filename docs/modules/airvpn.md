# airvpn module

`airvpn` is an optional, default-off TRANSIT module. It runs an unprivileged
LXC at `10.10.5.20` with `/dev/net/tun` and provides an AirVPN WireGuard exit
for eligible client modules.

Enable it explicitly and choose the provider selector:

```yaml
modules:
  airvpn:
    enabled: true
    servers: europe
  litellm:
    enabled: true
    network: airvpn
```

Only modules that declare network capability can use `network: airvpn`. The
provider must already be explicitly enabled; selecting AirVPN on a client does
not enable the provider. Internal service traffic, Core DNS/NTP, and modules
using `network: direct` retain their existing paths.

On the first confirmed deploy, the controller reads the API key from the
private file `~/.secrets/btcr-airvpn.key`, requests one IPv4 WireGuard profile
for the configured `servers` selector, validates it, and stores the normalized
profile as the encrypted site secret `airvpn_wireguard_config`. The API key and
WireGuard private key are not written to `site.yml`, generated model state,
Ansible variables, logs, or the guest image. A later deploy reuses the retained
profile.

Dry-run does not call AirVPN or write secrets. A missing retained profile is a
blocking readiness result until a confirmed deploy can generate it. To rotate
the retained profile explicitly:

```text
boetticher module secrets airvpn rotate --confirm --site ./my-boetticher
boetticher deploy --site ./my-boetticher --rotate-airvpn-profile
```

Rotation removes the retained profile; the next confirmed deploy generates a
replacement. The deployment firewall permits the AirVPN guest to reach only
the resolved provider WireGuard handshake endpoint, blocks direct-WAN and
TRANSIT-to-HOME fallback, and applies source policy routing without a direct
WAN fallback for selected clients. The guest kill switch remains blocking if
the profile, tunnel, or forwarding state is unavailable.

The generated firewall plan contains only resolved endpoint addresses, the
assigned tunnel address, and a non-secret profile digest. External gateway
mode emits the same routing and firewall requirements as an operator contract;
it does not claim that an external gateway enforces them. Successful
WireGuard handshakes, public egress, tunnel-down behavior, and HOME probe
blocking require live qualification.
