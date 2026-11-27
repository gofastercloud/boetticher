#!/usr/bin/env python3
"""groupthinQ dashboard: usage, tickets, agents, worktrees and spend in one terminal.

    python3 .claude/hooks/dash.py           live view, refreshes every 5s; Ctrl-C quits
    python3 .claude/hooks/dash.py --once    print one snapshot
    python3 .claude/hooks/dash.py up        tmux: Claude Code (orchestrator) left, dashboard right
    python3 .claude/hooks/dash.py up --code-mode   the same, with experimental Code Mode on

Reads local files, plus `gh issue list` and `git worktree list` once a minute.
Uses no Claude tokens. Stdlib only.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any

HERE = Path(__file__).resolve().parent


def _load_gtq() -> ModuleType:
    name = "gtq_for_dash"
    spec = importlib.util.spec_from_file_location(name, HERE / "gtq.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


gtq = _load_gtq()

AGENT_WINDOW_S = 30 * 60  # show agent runs active in the last 30 minutes
ACTIVE_S = 120  # transcript written this recently: the run is live
SLOW_TTL_S = 60  # gh and git refresh at most once a minute
SPEND_TTL_S = 300  # spend re-reads every transcript: every 5 minutes
# C0/C1 controls (ESC, OSC, CSI) and bidi overrides: issue titles and branch names are untrusted.
UNSAFE = re.compile("[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")
LABELS = ("in-progress", "needs-human", "ready-for-agent")
BAR = 20


@dataclass
class AgentRun:
    agent_type: str
    chain: str
    branch: str
    requests: int
    ctx: int
    usd: float
    last_tool: str
    age_s: float


@dataclass
class Snapshot:
    project: Path
    now: float
    windows: list[Any]
    pause: Any
    usage_age_s: float | None
    tickets: dict[str, list[tuple[int, str]] | str]
    agents: list[AgentRun]
    worktrees: list[tuple[str, str]] | str
    spend_today: float
    spend_week: float


@dataclass
class Cache:
    slow_at: float = -1e18
    spend_at: float = -1e18
    tickets: dict[str, list[tuple[int, str]] | str] = field(default_factory=dict)
    worktrees: list[tuple[str, str]] | str = field(default_factory=list)
    spend: tuple[float, float] = (0.0, 0.0)
    files: dict[tuple[str, float, int], AgentRun] = field(default_factory=dict)


# --------------------------------------------------------------------------- collectors


def _run(cmd: list[str], cwd: Path) -> str:
    """stdout of a short local command, or raise RuntimeError with a one-line reason."""
    try:
        out = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"{cmd[0]} unavailable: {exc}") from exc
    if out.returncode != 0:
        lines = (out.stderr.strip() or "failed").splitlines()
        raise RuntimeError(f"{cmd[0]}: {lines[-1][:80]}")
    return out.stdout


def tickets(project: Path) -> dict[str, list[tuple[int, str]] | str]:
    gh_bin = shutil.which("agent-gh") or "gh"
    out: dict[str, list[tuple[int, str]] | str] = {}
    for label in LABELS:
        cmd = [gh_bin, "issue", "list", "--state", "open", "--label", label, "--json", "number,title"]
        try:
            rows = json.loads(_run([*cmd, "--limit", "20"], project))
            out[label] = [(int(r["number"]), str(r["title"])) for r in rows]
        except (RuntimeError, ValueError, KeyError, TypeError) as exc:
            return dict.fromkeys(LABELS, str(exc))
    return out


def worktrees(project: Path) -> list[tuple[str, str]] | str:
    try:
        text = _run(["git", "worktree", "list", "--porcelain"], project)
    except RuntimeError as exc:
        return str(exc)
    out: list[tuple[str, str]] = []
    path = ""
    for line in text.splitlines():
        if line.startswith("worktree "):
            path = line.removeprefix("worktree ")
        elif line.startswith("branch "):
            out.append((path, line.removeprefix("branch refs/heads/")))
        elif line == "detached":
            out.append((path, "(detached)"))
    return out


def last_tool(path: Path) -> str:
    for rec in reversed(gtq.tail_records(path, 300_000)):
        msg = rec.get("message")
        if rec.get("type") != "assistant" or not isinstance(msg, dict):
            continue
        content = msg.get("content")
        if isinstance(content, list):
            for block in reversed(content):
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    return str(block.get("name", "?"))
    return "-"


def _agent_type(path: Path) -> str:
    meta = path.with_suffix(".meta.json")
    try:
        return str(json.loads(meta.read_text()).get("agentType") or "?")
    except (OSError, ValueError, AttributeError):
        return "?"


def agent_runs(project: Path, now: float, cache: Cache) -> list[AgentRun]:
    """Main sessions and subagent runs whose transcripts changed in the last 30 minutes."""
    tdir = gtq.project_dir_for(str(project))
    files = [(p, "main") for p in tdir.glob("*.jsonl")]
    files += [(p, "sub") for p in tdir.glob("*/subagents/*.jsonl")]
    runs: list[AgentRun] = []
    live_keys: set[tuple[str, float, int]] = set()
    for path, kind in files:
        try:
            st = path.stat()
        except OSError:
            continue
        if now - st.st_mtime > AGENT_WINDOW_S:
            continue
        key = (str(path), st.st_mtime, st.st_size)
        live_keys.add(key)
        run = cache.files.get(key)
        if run is None:
            reqs = list(gtq.iter_requests(path))
            if not reqs:
                continue
            chain = gtq.Chain("", "main", "main", path, reqs)
            run = AgentRun(
                agent_type="main" if kind == "main" else _agent_type(path),
                chain=path.stem.removeprefix("agent-")[:8],
                branch=chain.branch,
                requests=len(reqs),
                ctx=reqs[-1].ctx,
                usd=sum(r.usd for r in reqs),
                last_tool=last_tool(path),
                age_s=0.0,
            )
            cache.files[key] = run
        run.age_s = now - st.st_mtime
        runs.append(run)
    for stale in set(cache.files) - live_keys:  # one entry per transcript write otherwise
        del cache.files[stale]
    return sorted(runs, key=lambda r: r.age_s)


def spend(project: Path, now: float) -> tuple[float, float]:
    paths = sorted(gtq.project_dir_for(str(project)).glob("*.jsonl"))
    midnight = datetime.fromtimestamp(now).replace(hour=0, minute=0, second=0, microsecond=0)
    week = (midnight - timedelta(days=6)).timestamp()
    rows = gtq.report_rows_from_transcripts(paths, week)
    today_rows = gtq.report_rows_from_transcripts(paths, midnight.timestamp())
    return (sum(gtq._num(r["usd"]) for r in today_rows), sum(gtq._num(r["usd"]) for r in rows))


def collect(project: Path, cache: Cache, now: float | None = None) -> Snapshot:
    now = time.time() if now is None else now
    try:
        snap = gtq.load_usage(project) or {}
    except (gtq.UsageStateError, OSError):
        snap = {}  # pause_state below reports the problem
    written = snap.get("written_at")
    if now - cache.slow_at >= SLOW_TTL_S:
        cache.tickets = tickets(project)
        cache.worktrees = worktrees(project)
        cache.slow_at = now
    if now - cache.spend_at >= SPEND_TTL_S:
        try:
            cache.spend = spend(project, now)
        except Exception as exc:  # a malformed transcript must not kill the live view
            print(f"dash: spend: {exc}", file=sys.stderr)
        cache.spend_at = now
    try:
        agents = agent_runs(project, now, cache)
    except Exception as exc:
        print(f"dash: agents: {exc}", file=sys.stderr)
        agents = []
    return Snapshot(
        project=project,
        now=now,
        windows=list(gtq.usage_windows(snap.get("rate_limits"), now)),
        pause=gtq.pause_state(project, now),
        usage_age_s=now - float(written) if isinstance(written, (int, float)) else None,
        tickets=cache.tickets,
        agents=agents,
        worktrees=cache.worktrees,
        spend_today=cache.spend[0],
        spend_week=cache.spend[1],
    )


# --------------------------------------------------------------------------- render


def _ago(seconds: float) -> str:
    if seconds < 90:
        return f"{seconds:.0f}s"
    if seconds < 5400:
        return f"{seconds / 60:.0f}m"
    return f"{seconds / 3600:.1f}h"


def _k(n: int) -> str:
    return f"{n / 1000:.0f}k"


def render(s: Snapshot, width: int = 100) -> list[str]:
    threshold = float(gtq._env_int("GTQ_USAGE_STOP_PERCENT", 90))
    lines = [f"groundhog-agency · {s.project.name} · {datetime.fromtimestamp(s.now):%H:%M:%S}"]
    if s.pause is not None:
        lines.append(f"*** PAUSED: {s.pause.describe()} ***")

    lines += ["", "USAGE"]
    if not s.windows:
        lines.append("  no subscription usage yet (needs a Claude subscription and one status-line refresh)")
    for w in s.windows:
        pct = float(w.pct)
        filled = min(BAR, round(pct / 100 * BAR))
        flag = "  STOP" if pct >= threshold else ""
        lines.append(
            f"  {w.label:<6} [{'#' * filled}{'.' * (BAR - filled)}] {pct:3.0f}%  "
            f"resets {gtq.clock(w.resets_at)}{flag}"
        )
    if s.usage_age_s is not None and s.usage_age_s > 600:
        lines.append(f"  (usage last seen {_ago(s.usage_age_s)} ago: no live session is refreshing it)")

    lines += ["", "TICKETS"]
    for label in LABELS:
        got = s.tickets.get(label, [])
        if isinstance(got, str):
            lines.append(f"  {got}")
            break
        shown = ", ".join(f"#{n} {t}" for n, t in got[:6]) or "-"
        lines.append(f"  {label:<16}{len(got):>3}  {shown}")

    lines += ["", f"AGENTS (last {AGENT_WINDOW_S // 60} min)"]
    if not s.agents:
        lines.append("  none")
    for a in s.agents:
        state = "live" if a.age_s < ACTIVE_S else "idle"
        lines.append(
            f"  {state:<5}{a.agent_type:<12}{a.chain:<9}{(a.branch or '-')[:28]:<29}"
            f"ctx {_k(a.ctx):>5}  ${a.usd:>6.2f}  {a.requests:>4} req  {a.last_tool:<10} {_ago(a.age_s)} ago"
        )

    lines += ["", "WORKTREES"]
    if isinstance(s.worktrees, str):
        lines.append(f"  {s.worktrees}")
    else:
        lines += [f"  {b:<32} {p}" for p, b in s.worktrees] or ["  none"]

    lines += ["", f"SPEND (API list prices)  today ${s.spend_today:.2f}  ·  7 days ${s.spend_week:.2f}"]
    return [UNSAFE.sub("?", line)[:width] for line in lines]


# --------------------------------------------------------------------------- commands


def run_live(project: Path, interval: float) -> int:
    cache = Cache()
    try:
        while True:
            width = shutil.get_terminal_size().columns
            frame = "\n".join(render(collect(project, cache), width))
            sys.stdout.write("\x1b[H\x1b[2J" + frame + "\n")
            sys.stdout.flush()
            time.sleep(interval)
    except KeyboardInterrupt:
        return 0


def session_name(project: Path) -> str:
    return "gtq-" + (re.sub(r"[^A-Za-z0-9_-]", "-", project.name)[:40] or "repo")


CODE_MODE_MIN = (2, 1, 323)


def claude_version() -> tuple[int, ...] | None:
    try:
        out = subprocess.run(["claude", "--version"], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", out.stdout)
    return tuple(int(x) for x in m.groups()) if m else None


def claude_command(code_mode: bool) -> str | None:
    """The orchestrator pane's command, or None (with a message) if Code Mode can't run."""
    if not code_mode:
        return "claude"
    version = claude_version()
    if version is None or version < CODE_MODE_MIN:
        have = ".".join(map(str, version)) if version else "unknown"
        need = ".".join(map(str, CODE_MODE_MIN))
        print(f"Code Mode needs Claude Code {need} or later (found {have}). Run `claude update` first.")
        return None
    # Project settings can't turn Code Mode on, by design; the launching shell can.
    return "env CLAUDE_CODE_EXPERIMENTAL_CODE_MODE=1 claude"


def vendor_command(vendor: str, code_mode: bool) -> str | None:
    """The orchestrator pane's command for the chosen AI vendor."""
    if vendor == "codex":
        if code_mode:
            print("--code-mode is only supported with --vendor claude.")
            return None
        return "codex"
    return claude_command(code_mode)


def cmd_up(project: Path, code_mode: bool = False, vendor: str = "claude") -> int:
    agent_cmd = vendor_command(vendor, code_mode)
    if agent_cmd is None:
        return 1
    dash = f"python3 {shlex.quote(str(HERE / 'dash.py'))} --project {shlex.quote(str(project))}"
    tmux = shutil.which("tmux")
    if tmux is None:
        print(
            "tmux not found (macOS: brew install tmux). Without it, run these in two terminals:\n"
            f"  cd {shlex.quote(str(project))} && {agent_cmd}\n  {dash}"
        )
        return 1
    name = session_name(project)
    if subprocess.run([tmux, "has-session", "-t", name], capture_output=True, check=False).returncode:
        steps = [
            [tmux, "new-session", "-d", "-s", name, "-x", "200", "-y", "50", "-c", str(project), agent_cmd],
            [tmux, "set-option", "-t", name, "remain-on-exit", "on"],  # keep a pane's last words
            [tmux, "split-window", "-h", "-l", "40%", "-t", name, "-c", str(project), dash],
            [tmux, "select-pane", "-t", name, "-L"],
        ]
        for step in steps:
            done = subprocess.run(step, capture_output=True, text=True, check=False)
            if done.returncode:
                print(f"tmux failed at `{' '.join(step[1:3])}`: {done.stderr.strip()}", file=sys.stderr)
                return 1
    verb = "switch-client" if os.environ.get("TMUX") else "attach-session"
    os.execvp(tmux, [tmux, verb, "-t", name])


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="dash", description=(__doc__ or "").strip().splitlines()[0])
    p.add_argument("command", nargs="?", choices=["up"], help="up: open the tmux layout")
    p.add_argument(
        "--project", type=Path, default=Path(os.environ.get("CLAUDE_PROJECT_DIR") or HERE.parents[1])
    )
    p.add_argument("--once", action="store_true", help="print one snapshot and exit")
    p.add_argument("--vendor", choices=["claude", "codex"], default="claude", help="with `up`: AI CLI vendor")
    p.add_argument("--code-mode", action="store_true", help="with `up`: start Claude Code in Code Mode")
    p.add_argument("--interval", type=float, default=5.0)
    a = p.parse_args(argv)
    project = a.project.resolve()
    if a.command == "up":
        return cmd_up(project, a.code_mode, a.vendor)
    if a.once:
        print("\n".join(render(collect(project, Cache()), shutil.get_terminal_size().columns)))
        return 0
    return run_live(project, max(1.0, a.interval))


if __name__ == "__main__":
    sys.exit(main())
