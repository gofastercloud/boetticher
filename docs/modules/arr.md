# Video *arr module

`arr` is an optional, default-off research module for Sonarr and Radarr in one
unprivileged SERVERS LXC. It requires the AirVPN module and does not support a
direct network mode.

The guest receives its SERVERS address through a module-owned DHCP reservation.
The reservation and guest NIC use the same stable identity; it is not an
operator-owned workload reservation.

One nginx frontend will publish `sonarr.<domain>` and `radarr.<domain>` with the
existing Boetticher PKI and mandatory client certificates. Sonarr and Radarr
will listen only on loopback. Native application authentication is configured
off; the mTLS frontend remains the required access control boundary and this
behavior still needs live qualification.

External application traffic must use AirVPN. Direct-WAN fallback, LAB-to-HOME
forwarding or NAT, Proxmox access, and unrelated internal-zone access are not
part of the module contract.

Media uses one fixed 500 GiB `downloads` volume at
`/var/lib/arr/downloads`. Core places it on the dedicated Boetticher data disk
(`boetticher-thin`), so ARR cannot be enabled on the single-disk profile. The
volume is group-writable by Sonarr and Radarr, retained across rootfs
replacement, and excluded from Boetticher backups. There is no NFS client or
Raspberry Pi storage path in this module.

The appliance pins Sonarr `4.0.19.2979` and Radarr `6.3.0.10514` to official
Linux x64 release assets and verifies their published SHA-256 digests during
construction. The module remains research-only until the pinned artifacts,
application authentication behavior, NFS mount behavior, AirVPN egress, and
the mTLS negative and positive journeys are qualified on real infrastructure.
