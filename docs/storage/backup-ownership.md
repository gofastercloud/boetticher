# Backup ownership

Lab-in-a-Box guarantees backup coverage for its own platform guests through the clearly named Proxmox job `labinabox-platform`. The V1 generated policy includes only platform VM/LXC IDs:

```text
100 lab-fw-01
110 lab-dns-01
111 lab-dns-02
120 lab-monitor-01
130 lab-portal-01
```

The job is namespaced as Lab-in-a-Box-owned. Convergence must not overwrite or delete user-created backup jobs. User workloads remain user-owned; operators should create and maintain their own Proxmox backup policy if they need coverage. Doctor reports platform coverage without treating user workloads as drift.

Local backups on the same physical data disk are not independent disaster recovery. Offsite or independent backup is a future official module, not a V1 guarantee.
