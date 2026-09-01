# Module secrets

SOPS/Age remains the controller-side recovery authority. Modules declare secret
metadata only; they do not create secret stores or receive CA private keys.

Systemd credentials are the standard delivery mechanism. The consuming unit
receives only its declared credential through its credentials directory, not a
normal environment variable or public configuration file.

Operators manage declared operator-supplied values through the shared CLI:

```text
boetticher module secrets bifrost list --site ./my-boetticher
boetticher module secrets bifrost set openrouter_api_key --site ./my-boetticher
boetticher module secrets bifrost remove openrouter_api_key --confirm --site ./my-boetticher
```

`set` reads from a hidden TTY prompt when interactive. When deliberately
piped, it reads the value from stdin; the value must not be supplied as a
command argument. The command updates the encrypted platform document only;
run `boetticher deploy` separately to deliver the changed credential to a
service. `remove` is confirmation-gated and refuses a name shared by another
module. Secret listing and module status report only `present` or `missing`,
never values.

Enabling a module checks its declared operator secrets before saving or
deploying. An interactive `enable --confirm` prompts for missing values and
stores them in one encrypted update. Non-interactive enablement fails with
the corresponding `secrets set` commands, and `--dry-run` reports the gap
without prompting or changing state.

First-party `tailnet-router` declares `tailscale_auth_key` as operator-supplied
bootstrap material. `bifrost` declares the configured upstream secret
references, such as `openrouter_api_key`. These names are SOPS document keys,
not values in `site.yml`; their plaintext values must never enter generated
model/configuration output, artifacts, portal content, or logs. Tailscale
registration material is only needed when retained node state is absent.

The optional `streamdeck` module reuses Core's existing `pulse_api_token` from
the monitoring module. It is installed as an encrypted systemd credential only
after the controller has validated the mTLS Pulse read path; it is not an
operator-configured StreamDeck secret and is never written to the display
configuration.

Kea TSIG material is delivered through a systemd credential and materialised as
the smallest protected ephemeral secret file required by Kea D2. PowerDNS TSIG
material is an explicit third-party exception: PowerDNS stores its supported
TSIG metadata in its protected backend database. That database is sensitive
persistent state, excluded from logs and generated projections, and restored
from SOPS/Age during deployment.

Endpoint private keys are generated on the endpoint. TLS certificates may be
reissued after replacement; SSH host identity is persistent so bastion host-key
identity remains stable.

The monitoring module's `pulse_proxy_auth_secret` is an operator-supplied
random shared secret for the Pulse server and its nginx frontend. Boetticher
stores it only in the encrypted SOPS/Age platform document and projects it as
separate encrypted systemd credentials to `pulse.service` and `nginx.service`.
The nginx frontend materialises its proxy header at service start in protected
runtime state; the value is not placed in `site.yml`, generated public
configuration, command arguments, or logs.
