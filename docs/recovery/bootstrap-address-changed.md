# Changed bootstrap address

If the HOME-side Proxmox DHCP address changes, use the known new address with `homelab bootstrap-endpoint set ADDRESS`. Regenerate the SSH configuration and confirm the returned SSH host key matches the expected Proxmox identity. Lab-in-a-Box does not scan or guess addresses.
