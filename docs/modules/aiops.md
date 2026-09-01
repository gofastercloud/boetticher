# AIOps

`aiops` is an optional, default-off read-only incident-investigation module. It
runs unmodified HolmesGPT 0.40.0 on fixed LXC `lab-aiops-01` (VMID 240) at
`10.10.20.90` and accepts only a declared AI Router model alias:

```yaml
modules:
  aiops:
    enabled: true
    model_alias: operations-investigator
```

The module depends on Pulse monitoring, mandatory central logging, and the
LiteLLM-compatible AI Router module. That module is implemented by the
lightweight Bifrost router and is currently provisioned only for AIOps.
Provider credentials, upstream URLs, and provider model identifiers remain
owned by the router and are not valid AIOps configuration.

Activation is fail-closed. The router's local provider metadata must explicitly
prove chat completions, function calling, response schemas, at least 32,768
input tokens, and at least 1,200 output tokens. Core then runs a bounded live
tool-calling and response-schema canary through the declared alias. Unknown
metadata, an ambiguous alias, or either failed canary leaves all AIOps units
stopped and deployment fails with the failed qualification reason.

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

The `boetticher-aiops` adapter owns the webhook secret, separate Pulse read and
note identities, journal-query client identity, AI Router client identity and
the private incident database. Long-lived material is delivered through
systemd credentials. Holmes owns no persistent credential: its evidence calls
use a per-incident capability that expires within ten minutes. Holmes cannot
read the database or adapter credential directory, and its OpenAI-compatible
loopback key is a non-secret process identity accepted only while exactly one
incident capability is active.

Pulse's frontend binds the read and note certificates to different exact
method/path sets. The note token has `monitoring:write` scope because that is
Pulse 6.1.2's incident-note scope, but its certificate is rejected from every
other route, including acknowledge, clear, activate and configuration. The
logging endpoint accepts only the `aiops-log-read` certificate and a typed
host/unit/time/line query. There is no SSH evidence tier in the AIOps status contract.

Incidents are committed before webhook acceptance. Duplicate webhooks and the
60-second active-alert poll feed the same fingerprint transaction. Queue and
rate budgets defer execution without dropping admission; resolution requires
an explicit event or absence from three successful polls spanning at least
three minutes. Lifecycle and note transitions are idempotent.

The fixed limits are concurrency 1, queue 32, four starts per rolling hour, 24
per day, ten minutes, 12 Holmes steps, four follow-up evidence calls, 64 KiB
evidence, 200 journal lines over two hours, and 1,200 output tokens. Capacity
limits defer an already persisted incident; they never discard admission.
The adapter also enforces the 24,000-input-token ceiling conservatively across
the complete serialized model input. Because an alias can route to different
provider tokenizers, UTF-8 bytes are treated as the universal token upper bound;
this can admit less context but cannot exceed the approved budget.

Use `boetticher aiops status` for desired state and `--live` for bounded
loopback appliance state, including lifecycle counts, queue/running age, last
terminal result, 24-hour token totals and note delivery state. The status path
is not exposed on the external webhook listener. `doctor --live` additionally
uses a separate loopback-only diagnostic route to read and validate Pulse's
active-alert response, authenticate to the journal-query health path, and run
the bounded two-request tool/schema canary through the configured AI Router
alias. The AI Router check invokes the selected provider and may incur its
normal small request charge. Diagnostic responses expose only `PASS` or `FAIL`,
not upstream error or credential material. Live integration, negative network
tests, reboot recovery, backup/restore and lifecycle journeys remain separate
qualification gates until executed on supported infrastructure; a requested
gate fails with its next action until then.
