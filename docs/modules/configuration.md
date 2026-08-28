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
  aiops:
    enabled: false
    model_alias: selected-alias
  streamdeck:
    enabled: false
    brightness: 40
    refresh_seconds: 5
    request_timeout_seconds: 3
    default_page: overview
    pinned_guests: []
    storage_warning_percent: 80
    storage_critical_percent: 90
  printer:
    enabled: false
usb_exports:
  - module: streamdeck
    requirement: display
    port: "1-2.3"
    vendor_id: "0fd9"
    product_id: "006d"
    serial: "optional-device-serial"
  - module: printer
    requirement: serial
    port: "1-2.4"
    vendor_id: "1a86"
    product_id: "7523"
```

An omitted module map uses the defaults: DNS is mandatory, monitoring is
enabled, the managed firewall is enabled, and logging is mandatory. DNS has no
disable switch and accepts only `blocky` or `adguard` as its provider.

Use `boetticher config validate` before deployment, `boetticher config show`
to inspect normalized non-secret configuration, and `boetticher config schema`
to print the shipped generated JSON Schema. Unknown fields and unknown module names
are errors with a configuration path. `tailnet-router`, `litellm`, `streamdeck`, and `printer` are
default-off; LiteLLM exposes only the explicitly declared aliases and keeps
the referenced provider credentials in SOPS-managed secret state. `aiops` is
also default-off and accepts only `enabled` plus a declared `model_alias`;
provider, model, tool, and SSH fields are rejected. USB exports
bind only compiled-in named requirements to stable physical ports; Core resolves
raw USB or serial character devices according to the compiled requirement. They cannot
name device paths, VMIDs, or user workloads.
