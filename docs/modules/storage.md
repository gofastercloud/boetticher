# Module storage

Modules declare persistent volumes and one of `default`, `prefer-data-disk`, or
`require-data-disk`. Core resolves those declarations onto boetticher-owned
Proxmox storage. Modules never select physical disks, create PVs/VGs, format
devices, or run storage commands.

`prefer-data-disk` uses the dedicated boetticher storage profile when present
and safely falls back to standard storage. `require-data-disk` fails before
deployment when that profile is absent. Rootfs replacement preserves declared
volumes; ordinary disable retains them and explicit purge is required for
destruction.
