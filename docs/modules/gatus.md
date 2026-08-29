# Gatus

Gatus is an optional, default-off first-party module. Enable it with the
generic `boetticher module configure gatus` workflow. It creates
`lab-gatus-01` in SERVERS and publishes an HTTPS status page.

Checks are generated only from HTTPS URLs declared by enabled Boetticher-owned
module guests. Runtime state is ephemeral in memory; no Gatus database volume
is allocated. Arbitrary YAML, user endpoint DSL, user-workload URLs, and
adoption or lifecycle management of user workloads are unsupported. Arbitrary
or user-selected endpoint checks are deferred to later work.

Disable and purge use the normal module lifecycle. Gatus has no authority over
Pulse or Core monitoring, so disabling it leaves those projections unchanged.
Live DNS, HTTPS, endpoint, and authenticated-journey qualification remain
`NOT TESTED` until exercised on supported infrastructure.
