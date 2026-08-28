# Module configuration

`site.yml` is concise operator-authored configuration. Expanded components are
resolved state and are not accepted in the file.

```yaml
api_version: boetticher/v3
gateway:
  mode: managed
  upstream:
    mode: dhcp
    mac: 02:00:00:00:01:01 # generated and persisted by boetticher init
  publish:
    - service: dns
modules:
  dns:
    provider: blocky
  monitoring:
    enabled: false
  tailnet-router:
    enabled: false
  litellm:
    enabled: false
    upstreams:
      - name: openrouter
        base_url: https://openrouter.ai/api/v1
        api_key_secret: openrouter_api_key
    models:
      - alias: selected-alias
        upstream: openrouter
        model: selected/openrouter-model
```

An omitted module map uses the defaults: DNS is mandatory, monitoring is
enabled, the managed firewall is enabled, and logging is mandatory. DNS has no
disable switch and accepts only `blocky` or `adguard` as its provider.

Use `boetticher config validate` before deployment, `boetticher config show`
to inspect normalized non-secret configuration, and `boetticher config schema`
to print the shipped generated JSON Schema. Unknown fields and unknown module names
are errors with a configuration path. `tailnet-router` and `litellm` are
default-off; LiteLLM exposes only the explicitly declared aliases and keeps
the referenced provider credentials in SOPS-managed secret state.

The managed gateway uses one ordinary `wan0` vNIC on the existing HOME/upstream
bridge. `boetticher init` generates a locally administered unicast MAC with the
OS CSPRNG and persists it in `site.yml`; reserve that MAC in the upstream DHCP
server. The reserved IPv4 address remains upstream/operator state and is never
written to desired state.

`gateway.publish` is optional and currently accepts only `dns`. During deploy,
boetticher first brings up the gateway and DNS, observes the current DHCP
address, prefix, default gateway, and MAC, then installs only the matching TCP
and UDP port-53 DNAT and forward rules. If the observation is absent, stale, or
ambiguous, publication stays inactive and the deployment is held. Use
`boetticher verify --live` or `boetticher doctor --live` to inspect the effective
mapping, including the source-prefix restriction to the directly connected
upstream network.

The Core-owned USB export framework binds compiled-in named requirements to
stable physical ports; bindings cannot name device paths, VMIDs, or user
workloads.
