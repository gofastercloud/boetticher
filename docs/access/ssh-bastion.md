# SSH bastion

The controller reaches Proxmox through the HOME/upstream network, then uses
the forwarding-only `lab-jump` identity to reach modelled internal hosts.
Internal hosts use fixed IP addresses and canonical `HostKeyAlias` values, so
the path does not depend on internal DNS.

Controller-side Pulse reconciliation uses a temporary loopback SSH forward
through Proxmox; it does not add a controller route into the internal VLANs.

The managed gateway is an ordinary permitted host:

```text
ssh firewall
ssh lab-fw-01
```

The bastion has no useful shell, no TTY/X11/agent forwarding, and a generated
TCP/22 destination allow-list. Host-key validation remains enabled.

`labadmin` is an unprivileged durable SSH identity on the Proxmox host and
appliances. It has no general sudo authority and cannot perform platform
mutation through the host shell; the managed firewall exposes only fixed,
read-only inspection helpers. Bootstrap installs the operator key for a temporary
`root` SSH deployment path; Ansible uses that path with no `become`.
Successful convergence removes the root key and host root-login allowance.
Break-glass root access is reserved for bootstrap and recovery.
