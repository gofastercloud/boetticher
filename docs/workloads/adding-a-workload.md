# Adding a workload

User workloads do not require a boetticher module declaration. Create the VM/LXC with Proxmox, attach its NIC to `vmbr1`, choose the appropriate VLAN tag, and boot. DHCP supplies address/gateway/DNS/NTP where that zone permits it; a valid DHCP hostname can become a zone-qualified dynamic DNS name. Use a reservation or static application record when a service needs a stable name independent of its lease.

Do not edit generated inventory, SSH, portal, firewall, Zabbix, or backup files by hand. boetticher does not automatically monitor, back up, import, mutate, or delete the workload.

Choose zones deliberately: ordinary trusted devices use TRUSTED, internal services use SERVERS, test/corporate-managed/untrusted machines use SANDBOX, and MGMT is reserved for genuine infrastructure administration rather than merely important servers.

The model revision must change deterministically. Regenerate projections with `boetticher portal build` or the next normal converge operation, then run `boetticher doctor` to identify stale consumers. The workload is not operationally complete until its OpenTofu/Proxmox shape, OPNsense policy, DNS/NTP behavior, certificate state, Zabbix coverage, backup coverage, SSH destination restriction, portal entry, and verification journeys are all represented or explicitly marked `NOT TESTED`.

V1 does not invent arbitrary address allocation or remote-access behavior. A future official platform capability may use `boetticher module enable|disable`, but that extension point is not a generic application lifecycle API. A workload that needs new routing, a new provider, or a new security boundary remains a separate module design or user-owned integration.
