# Status (complete)
## Goal
Spec #184: Agent broker (`boetticher-agent-broker`) and Mac CLI (`agent-lab`) for safe, least-privilege Controller access — complete.
## Completed
- #185 → PR #191 (`internal/agentbroker` + `cmd/boetticher-agent-broker`)
- #186 → PR #190 (`internal/agentlab` + `cmd/agent-lab`)
- #187 → PR #193 (`boetticher controller agent-access status|enable|disable`)
- #188 → PR #192 (`package-controller.sh`, `install-controller.sh`, `Makefile` build)
- #189 → PR #194 (`docs/controller.md` restricted agent access guide)
## In flight
- None (0 open issues in `gofastercloud/boetticher`).
## Next
- When ready on the homelab: build/install the updated Controller payload on the Pi, run `agent-lab init` on the Mac, and run `boetticher controller agent-access enable --key '...' --yes` over your Secretive session.
- Optionally run `/retro` or start the next `/spec` (e.g. retiring the ~30k LOC legacy `site`/`proxmox`/`sops` stack).
