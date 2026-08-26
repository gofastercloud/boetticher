# Module secrets

SOPS/Age remains the controller-side recovery authority. Modules declare secret
metadata only; they do not create secret stores or receive CA private keys.

Systemd credentials are the standard delivery mechanism. The consuming unit
receives only its declared credential through its credentials directory, not a
normal environment variable or public configuration file.

Kea TSIG material is delivered through a systemd credential and materialised as
the smallest protected ephemeral secret file required by Kea D2. PowerDNS TSIG
material is an explicit third-party exception: PowerDNS stores its supported
TSIG metadata in its protected backend database. That database is sensitive
persistent state, excluded from logs and generated projections, and restored
from SOPS/Age during deployment.

Endpoint private keys are generated on the endpoint. TLS certificates may be
reissued after replacement; SSH host identity is persistent so bastion host-key
identity remains stable.
