#!/usr/bin/env python3
"""Run Holmes 0.40 against real local Victoria services and fake Bifrost.

Run this from a Linux fixture with HOLMES_PYTHON pointing at the venv created
from the pinned requirements lock. Only the model endpoint on port 4000 is
mocked; no paid provider or model call is made.
"""

import json
import os
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RUNNER = ROOT / "holmes-runner.py"
EXPECTED_TOOLS = {
    "list_prometheus_rules", "get_metric_names", "get_label_values",
    "get_all_labels", "get_series", "get_metric_metadata",
    "execute_prometheus_instant_query", "execute_prometheus_range_query",
    "victorialogs_query", "victorialogs_streams", "victorialogs_field_names",
    "victorialogs_field_values", "victorialogs_hits",
}


class BifrostFixture(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return

    def do_POST(self):
        if self.path != "/v1/chat/completions":
            self.send_json(404, {"error": "unsupported Bifrost route"})
            return
        size = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(size))
        if request.get("model") != "operations":
            self.send_json(400, {"error": "model alias was not stripped or declared"})
            return
        if request.get("max_tokens", request.get("max_completion_tokens")) != 1200 and request.get("max_completion_tokens") != 1200:
            self.send_json(400, {"error": "runner did not bound output tokens to 1200"})
            return
        tools = {item["function"]["name"] for item in request.get("tools", [])}
        if tools != EXPECTED_TOOLS:
            self.send_json(400, {"error": f"unexpected read-only tool schema: {sorted(tools)}"})
            return
        messages = request.get("messages", [])
        self.server.llm_requests.append(request)
        if self.server.mode == "malicious":
            tool_messages = [item for item in messages if item.get("role") == "tool"]
            if tool_messages:
                evidence = "\n".join(str(item.get("content", "")) for item in tool_messages).lower()
                if "failed to find tool shell_exec" not in evidence:
                    self.send_json(400, {"error": "unknown tool did not produce a tool-not-found error"})
                    return
                self.send_json(200, self.answer("I refused the unknown shell tool and performed no action."))
            else:
                self.send_json(200, {"id": "fixture", "object": "chat.completion", "model": "operations", "choices": [{"index": 0, "message": {"role": "assistant", "content": None, "tool_calls": [{"id": "bad", "type": "function", "function": {"name": "shell_exec", "arguments": "{}"}}]}, "finish_reason": "tool_calls"}]})
            return
        tool_messages = [item for item in messages if item.get("role") == "tool"]
        if tool_messages:
            # Holmes prefixes tool messages with request metadata that echoes
            # the query. Validate the returned payload after that boundary so
            # a query string or an error message cannot fake fixture evidence.
            try:
                payloads = {}
                for item in tool_messages:
                    suffix = item["content"].split("tool_call_metadata=", 1)[1]
                    _, end = json.JSONDecoder().raw_decode(suffix)
                    payloads[item["tool_call_id"]] = suffix[end:].strip()
                metric = json.loads(payloads["metrics"])
                logs = payloads["logs"]
                valid = (
                    set(payloads) == {"metrics", "logs"}
                    and metric["status"] == "success"
                    and any(row["metric"].get("__name__") == "up" and row["value"][1] == "1"
                            for row in metric["data"]["result"])
                    and "boetticher-phase5-fixture" in logs
                    and "phase5-native-journal-" in logs
                    and "No logs returned" not in logs
                )
            except (KeyError, IndexError, TypeError, ValueError):
                valid = False
            if not valid:
                self.send_json(400, {"error": "tool results did not contain fixture evidence"})
                return
            self.send_json(200, self.answer("The real VictoriaMetrics result is up=1 and the real VictoriaLogs result contains phase5-native-journal-."))
            return
        self.send_json(200, {"id": "fixture", "object": "chat.completion", "model": "operations", "choices": [{"index": 0, "message": {"role": "assistant", "content": None, "tool_calls": [{"id": "metrics", "type": "function", "function": {"name": "execute_prometheus_instant_query", "arguments": json.dumps({"query": "up{job=\"boetticher-lab-monitor-01\"}", "description": "fixture up check"})}}, {"id": "logs", "type": "function", "function": {"name": "victorialogs_query", "arguments": json.dumps({"query": "SYSLOG_IDENTIFIER:boetticher-phase5-fixture", "limit": 10})}}]}, "finish_reason": "tool_calls"}]})

    def answer(self, content):
        return {"id": "fixture", "object": "chat.completion", "model": "operations", "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20}}

    def send_json(self, status, value):
        encoded = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def run(mode=None):
    fixture = ThreadingHTTPServer(("127.0.0.1", 4000), BifrostFixture)
    fixture.mode = mode
    fixture.llm_requests = []
    threading.Thread(target=fixture.serve_forever, daemon=True).start()
    try:
        python = os.environ.get("HOLMES_PYTHON", "/opt/boetticher/observability/holmes/venv/bin/python")
        with tempfile.TemporaryDirectory() as credentials:
            credential = Path(credentials, "holmes-client-token")
            credential.write_text("fixture-token\n", encoding="utf-8")
            credential.chmod(0o600)
            environment = dict(os.environ, CREDENTIALS_DIRECTORY=credentials)
            result = subprocess.run([python, str(RUNNER), "--model-alias", "operations"], input="why is the fixture unhealthy?\n", text=True, capture_output=True, env=environment, timeout=180, check=False)
            combined = result.stdout + result.stderr
            if mode == "malicious":
                assert result.returncode == 0 and "refused" in combined.lower() and "shell_exec" in combined and ("could not find tool" in combined.lower() or "skipping tool execution" in combined.lower()), combined
            else:
                assert result.returncode == 0, combined
                assert "up=1" in result.stdout and "phase5-native-journal-" in result.stdout, result.stdout
            assert fixture.llm_requests, "Holmes did not call the fake Bifrost endpoint"
    finally:
        fixture.shutdown()
        fixture.server_close()


if __name__ == "__main__":
    run()
    run("malicious")
    print("Holmes fake-model integration: PASS")
