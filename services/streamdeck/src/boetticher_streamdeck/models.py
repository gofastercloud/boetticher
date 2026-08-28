from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

@dataclass(frozen=True)
class Resource:
    name: str
    kind: str
    status: str
    cpu: float | None = None
    memory: float | None = None
    storage: float | None = None

@dataclass(frozen=True)
class PulseState:
    status: str
    alerts: int
    resources: tuple[Resource, ...]
    received_at: datetime
    stale_reason: str = ""

    @property
    def age_seconds(self) -> int:
        return max(0, int((datetime.now(timezone.utc) - self.received_at).total_seconds()))

def optional_percent(value: Any) -> float | None:
    return float(value) if isinstance(value, (int, float)) and 0 <= float(value) <= 100 else None
