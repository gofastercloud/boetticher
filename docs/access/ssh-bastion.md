# SSH bastion

The controller reaches Proxmox through the HOME/upstream network, then uses
the forwarding-only `lab-jump` identity to reach modelled internal hosts.
Internal hosts use fixed IP addresses and canonical `HostKeyAlias` values, so
the path does not depend on internal DNS.

The managed gateway is an ordinary permitted host:

```text
ssh firewall
ssh lab-fw-01
```

The bastion has no useful shell, no TTY/X11/agent forwarding, and a generated
TCP/22 destination allow-list. Host-key validation remains enabled.
