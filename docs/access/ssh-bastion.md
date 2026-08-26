# SSH bastion

The normal path is:

```text
operator on HOME/upstream
        │
        │ SSH to recorded DHCP address
        ▼
lab-proxmox-01 / lab-bastion
        │ ProxyJump, forwarding only
        ▼
internal managed Linux host:22
```

OPNsense SSH is break-glass/recovery only. Proxmox is the supported bootstrap and recovery bastion even in virtual-only mode, with no physical `vmbr1` member and no direct TRUSTED/MGMT access.

`homelab ssh-config` writes `~/.ssh/config.d/labinabox.conf` by default. It creates the parent directory, writes atomically with mode `0600`, refuses overwrite unless `--force`, supports `--output -`, and never edits `~/.ssh/config` unless `--install-include` is explicitly requested. The output contains the model revision and generation timestamp but no secrets or private keys.

Internal entries use fixed IP `HostName`, canonical FQDN `HostKeyAlias`, `ProxyJump lab-bastion`, the modelled admin user, and an optional operator-selected `IdentityFile` with `IdentitiesOnly yes`. Thus `ssh dns01`, `ssh lab-dns-01`, and `ssh lab-dns-01.lab.home.arpa` share one canonical host-key identity even when internal DNS is unavailable.

The bastion destination list is generated from `SSHManaged`/`JumpAllowed` modules. It is not a general SOCKS proxy. Use `homelab ssh-config --check`, `homelab doctor`, and optionally `homelab verify --ssh-journey` to distinguish configuration correctness from a real authenticated journey.
