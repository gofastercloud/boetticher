# Appliance state

Built-in module appliances use three kinds of state.

`IMAGE-DERIVED` state is supplied by the pinned boetticher artifact: Debian,
qualified packages, application binaries, static templates, systemd units,
service accounts, and health tooling. It is replaceable.

`PERSISTENT` state is declared by the module and survives root filesystem
replacement:

- DNS01 and DNS02: PowerDNS database and stable SSH host identity;
- monitoring: PostgreSQL data and stable SSH host identity;
- firewall: Kea lease state and stable SSH host identity.

`DEPLOYMENT-DERIVED` state is regenerated from the desired model: runtime
configuration, DNS records, monitoring declarations, firewall policy,
certificates that can be reissued, and runtime credentials.

Endpoint TLS keys are generated locally and reissued when an appliance is
replaced. SSH host identity is persistent so the bastion host-key contract does
not change during an ordinary appliance upgrade.

Systemd credentials are the standard secret-delivery mechanism. A third-party
daemon may persist a secret in its own protected service datastore when its
supported operating model requires it. PowerDNS TSIG metadata is one explicit
example: the controller restores it into the protected PowerDNS backend. The
database is sensitive persistent state, excluded from generated public output,
and reconstructable from SOPS/Age.

Kea receives TSIG material through a systemd credential and a protected
ephemeral secret file. Plaintext values do not enter site.yml, plans, logs,
portal output, command arguments, or ordinary environment variables.

The recovery inputs are the boetticher artifact, SiteConfig, SOPS/Age recovery
state, CA authority, and declared persistent data/backups.
