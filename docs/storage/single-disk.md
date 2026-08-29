# Single-disk storage

The default system disk contains the root filesystem and directory-backed guest, backup, and data paths. All content shares one physical failure domain; a local backup does not protect against disk loss.

Choose `dedicated-data-disk` during the first guarded bootstrap when the host has a suitable separate device. Review the exact `/dev/disk/by-id/...` path and use `--storage-confirmed`. Do not let a module choose or format a device. Keep an independent copy of anything that must survive host loss.
