# SSH bastion and internal transport

The controller reaches Proxmox through the HOME/upstream network, then uses
the forwarding-only `lab-jump` identity to reach modelled internal hosts.
This is an implementation transport for Boetticher deployment and automation,
not a supported routine operator administration interface for Core appliances.
Internal hosts use fixed IP addresses and canonical `HostKeyAlias` values, so
the path does not depend on internal DNS.

Controller-side Pulse reconciliation uses a temporary loopback SSH forward
through Proxmox as `lab-jump`, constrained to the monitor HTTPS endpoint; it does
not add a controller route into the internal VLANs. Other bastion forwarding is
limited to the modelled SSH destinations.

Do not administer Core appliances by routinely logging in over SSH or by hand
mutating their state. Use the Boetticher CLI, native product UI/API where
appropriate, and generated portal/status surfaces. Explicit Proxmox
console/exec access is the documented break-glass path for recovery.

The bastion has no useful shell, no TTY/X11/agent forwarding, and a generated
TCP/22 destination allow-list. Host-key validation remains enabled.

`labadmin` is an unprivileged durable SSH identity used by the controller on
the Proxmox host and appliances. It has no general sudo authority and cannot
perform platform mutation through the host shell; the managed firewall exposes
only fixed, read-only inspection helpers. Bootstrap installs the operator key
for a temporary `root` SSH deployment path; Ansible uses that path with no
`become`.
Successful convergence removes the root key and host root-login allowance.
Break-glass root access is reserved for bootstrap and recovery.
