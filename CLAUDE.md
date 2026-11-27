@AGENTS.md

# Claude Code notes

AGENTS.md is the canonical contract; it was written for Codex. When running under Claude Code:

- Ignore the Codex model names (`gpt-5.6-*`) and `wait_agent`/`fork_turns` mechanics. Keep the intent: smallest suitable model/effort, small self-contained subagent briefs, sequential by default, one Git owner (use a Haiku/Sonnet subagent for Git work when delegating).
- Repo skills live in `.codex/skills/` (`boetticher-patching`, `reference-boundary-review`). Read the relevant `SKILL.md` directly when the task matches, or symlink them into `.claude/skills/`.
- Verification gates are unchanged: `make ci` before runtime handoff; `make maintenance-check` for `scripts/maintain-homelab.py`; docs-only edits need structure/link/diff checks.
- Commit, push, PR, deploy, and reboot still require scoped user authorization. Never touch `dist/`.
- Keep this file short; put rules in AGENTS.md, human docs in README.md and docs/.

<!-- groundhog-agency:start -->
## Compact instructions
When compacting, keep: ticket numbers and branches in flight, PR numbers, decisions and their reasons, open questions for the maintainer, and the next action. Drop: tool output, file contents, diffs, and anything already recorded in an issue or STATUS.md.
<!-- groundhog-agency:end -->
