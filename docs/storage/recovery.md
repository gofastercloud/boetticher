# Storage recovery

Same-disk backups are not disaster recovery. Preserve the private site repository, independent Age recovery copy, and required Proxmox backup material separately when recovery from disk loss matters.

For a failed appliance, start with [the recovery runbook](../recovery/recovery.md) and rebuild only resources that Boetticher proves it owns. For a failed data disk, keep the old device untouched until the recovery set and replacement storage have been checked. See [single-disk storage](single-disk.md) and [backup ownership](backup-ownership.md).
