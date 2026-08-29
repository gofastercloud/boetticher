# Gatus

Gatus is an optional, default-off first-party module for a small status page.
Enable it with `boetticher module configure gatus`, then run
`boetticher deploy`. It creates `lab-gatus-01` in SERVERS and publishes an
HTTPS status page for supported platform checks.

Checks are generated only from HTTPS URLs declared by enabled Boetticher-owned
module guests. Runtime state is ephemeral in memory; no Gatus database volume
is allocated. Arbitrary YAML, user endpoint DSL, user-workload URLs, and
adoption or lifecycle management of user workloads are unsupported. Arbitrary
or user-selected endpoint checks are not part of the 0.4 contract.

Disable and purge use the normal module lifecycle. Gatus has no authority over
Pulse or Core monitoring, so disabling it leaves those projections unchanged.
The generated page is reached through the platform HTTPS boundary; its
deployed authentication and endpoint checks still need live verification.
