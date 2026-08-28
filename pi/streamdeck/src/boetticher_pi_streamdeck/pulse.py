import json
import time
from datetime import datetime, timezone

import httpx

from .models import PulseState, Resource, optional_percent

MAX_RESPONSE = 4 * 1024 * 1024
MAX_RESOURCES = 400


class PulseClient:
    """Bounded, read-only Pulse client using the platform mTLS contract."""

    def __init__(self, base_url: str, token: str, cert: tuple[str, str], ca: str, timeout: float = 3.0):
        self.base_url = base_url.rstrip("/")
        self.total_timeout = timeout
        self.client = httpx.Client(
            headers={"Authorization": f"Bearer {token}"},
            cert=cert,
            verify=ca,
            follow_redirects=False,
            timeout=httpx.Timeout(timeout, connect=2.0),
        )

    def _json(self, path: str) -> object:
        deadline = time.monotonic() + self.total_timeout
        with self.client.stream("GET", self.base_url + path) as response:
            response.raise_for_status()
            chunks: list[bytes] = []
            size = 0
            for chunk in response.iter_bytes():
                if time.monotonic() > deadline:
                    raise httpx.TimeoutException("Pulse request exceeded total timeout")
                size += len(chunk)
                if size > MAX_RESPONSE:
                    raise ValueError("Pulse response exceeds 4 MiB")
                chunks.append(chunk)
        return json.loads(b"".join(chunks))

    def fetch(self) -> PulseState:
        summary = self._json("/api/state/summary")
        if not isinstance(summary, dict):
            raise ValueError("Pulse summary is not an object")

        resources: list[Resource] = []
        offset = 0
        while len(resources) < MAX_RESOURCES:
            page = self._json(f"/api/resources?source=proxmox&limit=100&offset={offset}&sort=name&order=asc")
            items = page.get("resources", page.get("data", [])) if isinstance(page, dict) else []
            if not isinstance(items, list):
                raise ValueError("Pulse resources is not a list")
            for item in items[: MAX_RESOURCES - len(resources)]:
                if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                    raise ValueError("malformed Pulse resource")
                metrics = item.get("metrics") if isinstance(item.get("metrics"), dict) else {}
                resources.append(
                    Resource(
                        item["name"],
                        str(item.get("type", "guest")),
                        str(item.get("status", "unknown")),
                        optional_percent(metrics.get("cpu")),
                        optional_percent(metrics.get("memory")),
                        optional_percent(metrics.get("storage")),
                    )
                )
            if len(items) < 100:
                break
            offset += 100

        return PulseState(
            str(summary.get("status", "unknown")),
            int(summary.get("alerts", summary.get("alertCount", 0))),
            tuple(resources),
            datetime.now(timezone.utc),
        )
