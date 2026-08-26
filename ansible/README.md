# Ansible integration boundary

Ansible is the guest convergence control plane for Debian guests. Roles will converge AdGuard Home and Chrony, Zabbix components, nginx/mTLS, and the generated portal artifact from the canonical model.

Credentials are supplied at runtime from SOPS-backed controller memory or approved secret mechanisms. Plaintext credentials, caches, and bootstrap state are never written to Git.
