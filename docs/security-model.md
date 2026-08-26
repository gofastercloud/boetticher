# Security model

OPNsense is the enforced inter-zone boundary with default-deny policy. Proxmox is not a router. The intended high-level policy is:

| Source | Internet | TRUSTED | SERVERS | SANDBOX | MGMT |
| --- | --- | --- | --- | --- | --- |
| TRUSTED | allowed | local | explicit services | denied | approved admin services |
| SERVERS | restricted egress | denied | local | denied | explicit monitor/admin paths |
| SANDBOX | allowed | denied | denied | policy-dependent | denied |
| MGMT | restricted | diagnostics | management | diagnostics | local |

SANDBOX receives DNS and NTP from OPNsense and does not receive the internal DNS addresses. The proposed DHCP `/32`/option-121 behavior is a hardening experiment, not an isolation claim. Routed isolation comes from OPNsense; virtual east-west SANDBOX isolation requires the Proxmox firewall; physical east-west isolation requires switch/client isolation.

The platform is IPv4-only in V1. Internal services use the installation’s private Root/Issuing CA hierarchy. Zabbix and the portal use TLS/mTLS according to the model. CA private keys remain in encrypted SOPS data; endpoint private keys are generated and retained outside Git. The portal never receives SOPS credentials or API tokens.

The initial trust transition starts on the HOME side and ends with scoped Proxmox/OPNsense identities. The `lab-jump` account is separate from the normal administrative account, has no useful shell, disables TTY/X11/agent forwarding, and is restricted to modelled internal TCP/22 destinations. SSH retains host-key verification and uses `HostKeyAlias` for canonical internal identities. No generated config may use `StrictHostKeyChecking no` or `/dev/null` known-hosts.
