"""Bounded, secret-free task timing callback for Boetticher deploys."""

from __future__ import annotations

import json
import os
import re
import time

from ansible.plugins.callback import CallbackBase


CALLBACK_VERSION = 2.0
CALLBACK_TYPE = "aggregate"
CALLBACK_NAME = "boetticher_timing"
CALLBACK_NEEDS_WHITELIST = True

_MAX_TEXT = 512
_MAX_MARKERS = 64
_MARKER_RE = re.compile(
    r"^boetticher-observation dns-metadata-drift "
    r"([A-Za-z0-9.-]+) "
    r"(ALLOW-DNSUPDATE-FROM|NOTIFY-DNSUPDATE|TSIG-ALLOW-DNSUPDATE) "
    r"([0-9]+) ([0-9]+) ([0-9a-f]{16})$"
)


class CallbackModule(CallbackBase):
    """Write one bounded JSON object per completed task, and nothing else."""

    def __init__(self):
        super().__init__()
        self._path = os.environ.get("BOETTICHER_ANSIBLE_TIMING_FILE", "")
        self._started = {}
        self._batch = None

    @staticmethod
    def _text(value, limit=_MAX_TEXT):
        return str(value or "")[:limit]

    @staticmethod
    def _markers(result):
        markers = []
        results = result._result.get("results")
        if not isinstance(results, list):
            results = [result._result]
        for item in results:
            for line in item.get("stdout_lines", []) or []:
                match = _MARKER_RE.fullmatch(str(line).strip())
                if not match:
                    continue
                marker = f"dns-metadata-drift:{match.group(1)}:{match.group(2)}:{match.group(3)}:{match.group(4)}:{match.group(5)}"
                if marker not in markers:
                    markers.append(marker)
                if len(markers) >= _MAX_MARKERS:
                    return markers
        return markers

    def v2_runner_on_start(self, host, task):
        if not self._path:
            return
        key = (self._text(host.get_name(), 256), self._text(task._uuid, 128))
        self._started[key] = (time.monotonic(), task)

    def _write(self, entry):
        try:
            with open(self._path, "a", encoding="utf-8") as output:
                output.write(json.dumps(entry, separators=(",", ":")) + "\n")
        except OSError:
            # Timing is diagnostic only and must never change deployment
            # success or failure.
            return

    def _finish_batch(self):
        if not self._path or self._batch is None:
            return
        started, task = self._batch
        self._write({
            "event": "task_batch",
            "task": self._text(task.get_name()),
            "path": self._text(task.get_path()),
            "duration_ms": max(0, round((time.monotonic() - started) * 1000)),
        })
        self._batch = None

    def v2_playbook_on_task_start(self, task, is_conditional):
        # The interval between task-start callbacks includes strategy,
        # controller scheduling, and connection/setup gaps that per-host
        # runner callbacks do not expose.
        self._finish_batch()
        if self._path:
            self._batch = (time.monotonic(), task)

    def v2_playbook_on_stats(self, stats):
        self._finish_batch()

    def _record(self, result, status):
        if not self._path:
            return
        host = self._text(result._host.get_name(), 256)
        task = result._task
        key = (host, self._text(task._uuid, 128))
        started = self._started.pop(key, None)
        if started is None:
            return
        duration_ms = max(0, round((time.monotonic() - started[0]) * 1000))
        entry = {
            "host": host,
            "task": self._text(task.get_name()),
            "path": self._text(task.get_path()),
            "status": status,
            "duration_ms": duration_ms,
            "changed": bool(result._result.get("changed", False)),
        }
        markers = self._markers(result)
        if markers:
            entry["markers"] = markers
        self._write(entry)

    def v2_runner_on_ok(self, result):
        self._record(result, "ok")

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self._record(result, "failed")

    def v2_runner_on_unreachable(self, result):
        self._record(result, "unreachable")

    def v2_runner_on_skipped(self, result):
        self._record(result, "skipped")
