# Module configuration

`site.yml` is concise operator-authored configuration. Expanded components are
resolved state and are not accepted in the file.

```yaml
api_version: boetticher/v3
gateway:
  mode: managed
modules:
  monitoring:
    enabled: false
```

An omitted module map uses the defaults: DNS is mandatory, monitoring is
enabled, and the managed firewall is enabled. DNS has no disable switch.

Use `boetticher config validate` before deployment, `boetticher config show`
to inspect normalized non-secret configuration, and `boetticher config schema`
to locate `schemas/site.schema.json`. Unknown fields and unknown module names
are errors with a configuration path.
