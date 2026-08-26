# Backup ownership

boetticher guarantees backup coverage for its own platform guests through the clearly named Proxmox job `boetticher-platform`. The V1 generated policy includes only platform VM/LXC IDs:

```text
100 lab-fw-01
110 lab-dns-01
111 lab-dns-02
120 lab-monitor-01
130 lab-portal-01
```

Each managed guest also receives a canonical Proxmox tag set. All five V1
guests carry `boetticher`, `managed`, `platform`, `infra`, and `backup`, plus
role tags such as `network`, `dns`, `ntp`, `observability`, or `portal`.

The `backup` tag is the model-level selection signal. boetticher turns the
tagged, declared guests into the explicit VMID list submitted to the
Proxmox backup job. This keeps the job bounded to boetticher-owned resources;
a user guest is never included merely because it happens to use a similar
tag. Tags are useful for visibility and filtering in Proxmox, but they do not
change the ownership boundary.

The job is namespaced as boetticher-owned. Convergence must not overwrite or delete user-created backup jobs. User workloads remain user-owned; operators should create and maintain their own Proxmox backup policy if they need coverage. Doctor reports platform coverage without treating user workloads as drift.

Local backups on the same physical data disk are not independent disaster recovery. Offsite or independent backup is a future official module, not a V1 guarantee.
