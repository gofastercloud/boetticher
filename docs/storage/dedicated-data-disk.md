# Dedicated data disk

The OS disk contains Proxmox root. The data disk contains `vg_boetticher` with
guest thin storage, a backup filesystem mounted at `/srv/boetticher/backups`,
and reserved capacity. Guest databases remain ordinary guest disks.

For this profile, convergence registers the fixed Proxmox directory storage
`boetticher-backups` for that path and uses it for the platform backup job. The
mount must already be present before `boetticher converge`; a missing mount or
conflicting Proxmox storage definition stops convergence rather than sending
backups to an unexpected disk.
