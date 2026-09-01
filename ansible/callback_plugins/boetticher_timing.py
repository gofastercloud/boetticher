"""Bounded, secret-free task timing callback for Boetticher deploys."""

from __future__ import annotations

import json
import os
import time

from ansible.plugins.callback import CallbackBase


CALLBACK_VERSION = 2.0
CALLBACK_TYPE = "aggregate"
CALLBACK_NAME = "boetticher_timing"
CALLBACK_NEEDS_WHITELIST = True

_MAX_TEXT = 512


class CallbackModule(CallbackBase):
    """Write one bounded JSON object per completed task, and nothing else."""

    def __init__(self):
        super().__init__()
        self._path = os.environ.get("BOETTICHER_ANSIBLE_TIMING_FILE", "")
        self._started = {}

    @staticmethod
    def _text(value, limit=_MAX_TEXT):
        return str(value or "")[:limit]

    def v2_runner_on_start(self, host, task):
        if not self._path:
            return
        key = (self._text(host.get_name(), 256), self._text(task._uuid, 128))
        self._started[key] = (time.monotonic(), task)

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
        try:
            with open(self._path, "a", encoding="utf-8") as output:
                output.write(json.dumps(entry, separators=(",", ":")) + "\n")
        except OSError:
            # Timing is diagnostic only and must never change deployment
            # success or failure.
            return

    def v2_runner_on_ok(self, result):
        self._record(result, "ok")

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self._record(result, "failed")

    def v2_runner_on_unreachable(self, result):
        self._record(result, "unreachable")

    def v2_runner_on_skipped(self, result):
        self._record(result, "skipped")
