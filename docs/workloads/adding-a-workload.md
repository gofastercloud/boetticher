# Adding a workload

Use Proxmox's Web UI, `qm`, `pct`, Ansible, Pulumi, or another tool for
user-owned workloads. boetticher does not provide a generic guest lifecycle
command.

Create the guest, attach its NIC to `vmbr1`, choose a zone VLAN, and boot. A
normal DHCP client receives the zone's address, gateway, DNS, NTP, Internet
policy, and isolation automatically. A valid DHCP hostname may be published in
the zone-qualified dynamic DNS namespace. That publication does not import,
monitor, back up, mutate, or otherwise adopt the workload.

Use a reservation or a deliberate application DNS record when a service name
must remain stable independently of a lease identity.
