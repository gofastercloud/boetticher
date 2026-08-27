# Module configuration

`site.yml` is concise operator-authored configuration. Expanded components are
resolved state and are not accepted in the file.

```yaml
api_version: boetticher/v3
gateway:
  mode: managed
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
