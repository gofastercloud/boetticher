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
  aiops:
    enabled: false
    model_alias: selected-alias
  printer:
    enabled: false
usb_exports:
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
are errors with a configuration path. `tailnet-router`, `litellm`, and `printer` are
default-off; LiteLLM exposes only the explicitly declared aliases and keeps
the referenced provider credentials in SOPS-managed secret state. `aiops` is
also default-off and accepts only `enabled` plus a declared `model_alias`;
provider, model, tool, and SSH fields are rejected.

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
workloads. Core resolves raw USB or serial character devices according to the
compiled requirement.

## Module configuration workflow

First-party module authors declare operator-facing fields once on the module
definition, alongside dependencies, USB requirements, and secret declarations.
The field metadata supplies the key, typed input kind, prompt, bounds,
required/default status, allowed values or resolver, and sensitive
classification. Core uses that declaration to generate the generic
`boetticher module configure MODULE` workflow; modules do not implement
individual wizards. The typed `ModulesConfig` structs remain the persisted
configuration authority.

`module configure` changes desired state only. It does not deploy guests,
reconcile USB devices in live infrastructure, or run a module. Review its
redacted plan and run `boetticher deploy` separately. Optional-module
dependencies are resolved by the existing registry and are shown in the plan.
Disabling retains owned resources unless the established, separately confirmed
purge operation is used.

Use the interactive workflow for normal operation:

```text
boetticher module configure printer
boetticher module configure aiops
```

`--dry-run` performs validation and prints a plan without writing. `--json`
emits a redacted machine-readable plan and never prompts; use `--enabled`,
repeatable typed `--set KEY=VALUE`, and `--usb REQUIREMENT=PORT` for safe
automation. A non-interactive apply requires `--confirm`. Missing required
fields, model aliases, or USB bindings are `HOLD`, never guessed.

Operator credentials are never accepted as arguments. Declared
operator-supplied secrets are read from a terminal without echo or from stdin,
then written through the existing SOPS/platform-secret machinery. Secret
values are structurally excluded from plans, JSON, logs, generated portal
content, and errors. Configuration and secret updates use atomic file
replacement with rollback if the second replacement fails.

For a declared USB requirement, configure discovers compatible parent devices
using the existing physical-port and VID/PID identity model and presents
numbered choices. Ambiguous or incompatible identities are rejected. The
selected device is stored in the existing `usb_exports` representation, which
the normal USB reconciler consumes; no device path or second USB configuration
is introduced.
