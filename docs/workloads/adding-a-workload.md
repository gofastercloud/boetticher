# Adding a workload

Add one module declaration to the private `site.yml` with its zone, fixed address, aliases, SSH policy, mTLS, monitoring, backup, and URL metadata. Do not edit generated inventory, SSH, portal, firewall, Zabbix, or backup files by hand.

The model revision must change deterministically. Regenerate projections with `homelab portal build` or the next normal converge operation, then run `homelab doctor` to identify stale consumers. The workload is not operationally complete until its OpenTofu/Proxmox shape, OPNsense policy, DNS/NTP behavior, certificate state, Zabbix coverage, backup coverage, SSH destination restriction, portal entry, and verification journeys are all represented or explicitly marked `NOT TESTED`.

V1 does not invent arbitrary address allocation or remote-access behavior. A future workload that needs new routing, a new provider, or a new security boundary is a module design change and must extend the canonical model first.
