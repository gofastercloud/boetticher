# AIOps

`aiops` is an optional, default-off read-only incident-investigation module. It
runs unmodified HolmesGPT 0.40.0 on `lab-aiops-01` and accepts only a declared
AI Router model alias:

```yaml
modules:
  aiops:
    enabled: true
    model_alias: operations-investigator
```

The module depends on Pulse monitoring, mandatory central logging, and
LiteLLM. Provider credentials, upstream URLs, and provider model identifiers
remain owned by LiteLLM and are not valid AIOps configuration.

## Authority boundary

AIOps investigates only. It cannot acknowledge or clear alerts, restart
services, run remediation, use SSH, execute shell commands, or reach the
Internet. Its only external write is an incident note through the exact Pulse
note endpoint.

Untrusted alert, metric, journal or probe content may influence arguments only
within an already-authorized typed tool schema. Evidence can never create or
activate a new tool, endpoint, hostname, path, command, credential, network
destination or mutation authority.

Holmes runs as a separate Unix user with loopback networking only. Raw evidence
and reconstructed prompts are transient; terminal state retains only reports,
references, hashes, usage and audit metadata for 30 days.

The fixed limits are concurrency 1, queue 32, four starts per rolling hour, 24
per day, ten minutes, 12 Holmes steps, four follow-up evidence calls, 64 KiB
evidence, 200 journal lines over two hours, and 1,200 output tokens. Capacity
limits defer an already persisted incident; they never discard admission.

Use `boetticher aiops status` for desired state and `--live` for bounded
appliance state. Live integration and lifecycle journeys remain `NOT TESTED`
until executed on supported infrastructure.
