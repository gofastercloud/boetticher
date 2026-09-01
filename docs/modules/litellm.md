# litellm module

`litellm` is an optional, default-off first-party AI API router at
`10.10.20.60` in SERVERS. Clients use only explicitly declared provider-
neutral model aliases from typed `site.yml` configuration; undeclared model
identifiers are rejected and upstream credentials remain server-side.

Configure it with the typed fields `upstreams`, `models`, and
`api_key_secret`. Add secret values with `boetticher module secrets litellm`
or the configure workflow; secret values are read from a prompt or stdin and
never belong in `site.yml` or command arguments.

The appliance exposes only nginx HTTPS on port 443 with required client
certificates from the existing Boetticher PKI. Nginx proxies to the
lightweight Bifrost backend on loopback `127.0.0.1:4000`; Bifrost implements
the OpenAI-compatible LiteLLM contract currently required by AIOps, including
declared model aliases and chat completions. No plaintext listener or second
Boetticher client API-key layer is introduced. The configured upstream API
credential is delivered as an ephemeral systemd credential and is never part
of the site model, artifact, generated non-secret projection, portal, or
logs.

Core composes outbound policy from the configured HTTPS upstream endpoints,
plus DNS/NTP and mandatory central logging. Unknown upstream destinations
remain denied. External gateway mode emits this requirement as an operator
contract and performs no external firewall mutation.

The endpoint TLS identity is retained on a module-owned persistent volume.
The `boetticher-litellm` artifact contains the Bifrost Go router and nginx; it
does not install Python, a virtual environment, or the former LiteLLM package
stack. Artifact construction qualifies the appliance with smoke, SBOM,
vulnerability, and content-digest gates. Disable retains the module's owned
state; purge is a separately confirmed destructive operation. Live deployment,
mTLS client journeys, upstream requests, and recovery still need current
infrastructure verification.
