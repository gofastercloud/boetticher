# Ansible integration boundary

Ansible is a bounded runtime-configuration transport for qualified Debian
appliances and Core host configuration. The generated inventory uses fixed
internal IPs, canonical `HostKeyAlias` values, and `ProxyJump lab-bastion`; it
does not depend on internal DNS. Generated variables include the model revision
and IPv4-only contract and are streamed through `--extra-vars @/dev/stdin` rather than
written as a plaintext file. Appliance software and versions come from the
qualified immutable artifacts; these roles do not install application stacks.

The roles establish the base/Chrony/nginx boundaries and provide the module-owned hooks for AdGuard Home, Pulse, mTLS, and portal publication. Exact package/image pins, service credentials, and endpoint-specific configuration remain release qualification inputs rather than being invented as mutable plaintext defaults. Credentials must come from SOPS-backed controller memory or an approved runtime mechanism. Plaintext credentials, caches, and bootstrap state never belong in Git.
