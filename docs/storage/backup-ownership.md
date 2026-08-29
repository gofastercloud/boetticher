# Backup ownership

boetticher defines and provisions intended backup coverage for its own
platform guests through the
clearly named Proxmox job `boetticher-platform`. In the default managed
configuration, the platform backup set contains these platform VM/LXC IDs:

```text
100 lab-fw-01
110 lab-dns-01
111 lab-dns-02
120 lab-monitor-01
130 lab-portal-01
140 lab-log-01
```

The actual list is derived from active boetticher-owned guests carrying the
backup contract. External gateway mode therefore has no VM 100, and disabling
monitoring has no VM 120 in the active backup set. Each managed guest also
receives a canonical Proxmox tag set, including the backup contract where
applicable.

The firewall guest backup includes its declared telemetry volume at
`/var/lib/boetticher/firewall-telemetry` as well as the Kea lease and SSH
identity volumes. The telemetry volume is platform state, not an external
database or a user workload.

The logging guest is included in the platform backup set. Its bounded central
journal volume at `/var/log/journal/remote` is explicitly `backup=false`
because endpoint journals remain available for recovery and the central copy
is high-churn operational data. The logging appliance and its declared
volume remain boetticher-owned.

The `backup` tag is the model-level selection signal. boetticher turns the
tagged, declared guests into the explicit VMID list submitted to the
Proxmox backup job. This keeps the job bounded to boetticher-owned resources;
a user guest is never included merely because it happens to use a similar
tag. Tags are useful for visibility and filtering in Proxmox, but they do not
change the ownership boundary.

The job is namespaced as boetticher-owned. Deployment must not overwrite or delete user-created backup jobs. User workloads remain user-owned; operators should create and maintain their own Proxmox backup policy if they need coverage. Doctor reports platform coverage without treating user workloads as drift.

Local backups on the same physical data disk are not independent disaster recovery. Check the current backup job and its last successful run before relying on it; this document describes intended coverage, not live freshness. Offsite or independent backup is not part of the current platform contract.
