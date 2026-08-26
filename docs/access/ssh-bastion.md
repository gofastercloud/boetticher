# SSH bastion

From HOME/upstream, SSH first reaches Proxmox using the recorded bootstrap address. Internal hosts use `ProxyJump lab-bastion` and fixed internal IPs, so access does not depend on internal DNS. The `lab-jump` identity is forwarding-only and restricted to modelled TCP/22 destinations. OPNsense SSH is break-glass only.

Run `homelab ssh-config --install-include` explicitly to install the `~/.ssh/config.d/*` include. Use `homelab ssh-config --check` and `homelab doctor` to check revision and safety.
