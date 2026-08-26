# Recovery

The minimum control-plane recovery set is the private site repository plus an independent Age private-identity copy.

- Proxmox root loss: fresh supported Proxmox, bootstrap, and reconstruct from site state.
- OPNsense loss: recreate the VM and reapply the authenticated API convergence.
- DNS loss: recreate either DNS node independently; the pair is service redundancy, not host redundancy.
- Changed HOME DHCP address: run `homelab bootstrap-endpoint set ADDRESS`, then regenerate SSH configuration.
- Lost operator device: issue a new client certificate and SSH key; revoke the old certificate.
