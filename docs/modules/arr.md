# Media *arr module

`arr` **1.0.1** is an optional, default-off research module containing native
Sonarr, Radarr, Lidarr, Prowlarr, and qBittorrent in one unprivileged SERVERS LXC.
It requires AirVPN and the dedicated data disk. No Docker or nested containers
are required. The guest remains `lab-arr-01`, VMID 270, at `10.10.20.110`, with
its declaration-owned DHCP reservation and mandatory `network: airvpn`.

## Deployment and application setup

`deploy` wires Prowlarr to Sonarr, Radarr, and Lidarr with full indexer sync,
registers the local qBittorrent client, and configures library roots,
completed-download handling, and hardlinks. Download categories are
`boetticher-tv`, `boetticher-movies`, and `boetticher-music`.

Add indexers in Prowlarr and choose quality preferences in the applications.
Boetticher preserves operator settings. A newly created Lidarr library root
uses its oldest existing quality and metadata profiles; those profiles remain
operator-managed. Connections named `boetticher-*` are deployment-owned.
Ambiguous connections to the same local service require operator resolution.
Repeated deployment compares settings and does not create duplicates.

Nginx publishes `sonarr.<domain>`, `radarr.<domain>`, `lidarr.<domain>`,
`prowlarr.<domain>`, and `qbittorrent.<domain>` with mandatory Boetticher operator
client certificates. All web/API backends bind to loopback. Native localhost
login exemptions remain behind the mTLS boundary; qBittorrent keeps CSRF and
host-header validation. API credentials stay in protected guest-local state.
The torrent peer listener is separate from the WebUI.

## Storage and upgrades

The existing 500 GiB volume at `/var/lib/arr/downloads` remains on
`boetticher-thin`. Downloads use `incoming/{tv,movies,music}` and libraries use
`library/{tv,movies,music}` beneath that mount, allowing same-filesystem
hardlinks. Media is retained across rootfs replacement and excluded from
backups; application state and TLS identities remain backed up. No NFS client
or Raspberry Pi storage path is used.

Readarr is retired and stopped if present. Its state and media are retained;
UID 2203 is not reassigned. Existing Sonarr, Radarr, and Lidarr identities and
state paths are preserved. Existing media is not moved automatically.

## AirVPN peer port forwarding

Reserve a **TCP and UDP** port in AirVPN's client area for the device used by
the retained Boetticher WireGuard profile. Use matching remote and local ports.
Configure the reservation with the existing command:

```sh
boetticher module configure airvpn --site ./my-boetticher --non-interactive --set qbittorrent_port=45678 --confirm
```

`45678` is an example, not an allocated port. The command changes desired state;
`deploy` applies it. Valid reservations are 2049–65535 excluding ARR web/API
ports. `0` disables inbound forwarding and uses peer port 6881 for outbound
connections. The provider reservation is not created or verified by this setting.

Boetticher applies the same port to qBittorrent, tunnel-only DNAT/SNAT on the
AirVPN guest, and an exact AirVPN-to-ARR TCP/UDP gateway allowance. SNAT keeps
replies on the same AirVPN path. ARR rejects new peer connections from other
sources. Disabling ARR or setting the port to zero removes generated forwarding.
UPnP/NAT-PMP and local peer discovery are disabled. External egress continues
through AirVPN, with direct-WAN fallback and LAB-to-HOME forwarding/NAT denied.
No HOME router port forwarding or WebUI exposure is required.

## Maintenance and qualification

The appliance pins Sonarr `4.0.19.2979`, Radarr `6.3.0.10514`, Lidarr
`3.1.4.5029`, Prowlarr `2.5.2.5491`, and Debian `qbittorrent-nox` `5.1.0-2`.
Release archives are checksum-verified; Debian packages use the authenticated
snapshot. Application self-updates are disabled. Software changes follow the
normal appliance build, scan, and replacement workflow.

Native dependency/layout choices were checked against
[Proxmox Community Scripts](https://github.com/community-scripts/ProxmoxVE/blob/9996ed71ba50500b7156cfcf2ef519415d9e0187/install/sonarr-install.sh).
No upstream installer is forked, fetched, or executed during deployment.

The module remains research-only until the appliance and live journeys are
qualified: fresh deployment, idempotent redeploy, retained-state replacement,
valid/invalid client certificates, closed backend ports, VPN egress,
tunnel-down blocking, and reserved inbound TCP/UDP connectivity. Use official
Linux ISO torrents and verify their published checksums. Test media import and
hardlinks separately with a permitted media fixture. A successful download
alone does not prove inbound forwarding or the kill switch.
