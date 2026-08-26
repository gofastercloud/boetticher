# Dedicated data disk

The dedicated profile is self-contained. Set a stable device identity in the
private site configuration:

```yaml
storage_profile: dedicated-data-disk
storage_device: /dev/disk/by-id/ata-EXAMPLE-DATA-DISK
```

During `boetticher bootstrap`, after the operator reviews the device and adds
`--storage-confirmed`, boetticher checks that it is not the Proxmox system disk,
has no mounted filesystems, existing LVM use, or filesystem signatures, and
then creates the fixed layout:

```text
data disk
└── vg_boetticher
    ├── thinpool       70% of the VG (guest disks)
    ├── backup         20% of the VG, ext4
    │   └── /srv/boetticher/backups
    └── 10% reserved
```

The operation uses the stable `/dev/disk/by-id/...` identity, persists the
backup mount by filesystem UUID, and registers `boetticher-thin` and
`boetticher-backups` in Proxmox. Repeating bootstrap adopts the exact expected
layout; an unexpected existing volume group stops rather than reformatting.

The system disk remains the Proxmox root device. Guest databases remain
ordinary guest disks, including PostgreSQL on the monitor guest.

The data disk is still one physical failure domain. Local backups provide
rollback and recovery convenience, not independent disaster recovery.
