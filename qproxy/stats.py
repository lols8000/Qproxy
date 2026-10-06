from __future__ import annotations

from collections import Counter, deque
from datetime import datetime, timezone
import json
from pathlib import Path
from threading import RLock
from typing import Any


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class StatsStore:
    def __init__(self, path: str | Path, recent_limit: int = 80, save_every: int = 25) -> None:
        self.path = Path(path)
        self.recent_limit = recent_limit
        self.save_every = max(1, save_every)
        self._lock = RLock()
        self.started_at = _utc_now()
        self.total_requests = 0
        self.blocked_requests = 0
        self.allowed_requests = 0
        self.blocked_ads = 0
        self.blocked_trackers = 0
        self.bytes_relayed = 0
        self.top_blocked: Counter[str] = Counter()
        self.recent: deque[dict[str, Any]] = deque(maxlen=recent_limit)
        self._dirty_events = 0
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        with self._lock:
            self.total_requests = int(data.get("total_requests", 0))
            self.blocked_requests = int(data.get("blocked_requests", 0))
            self.allowed_requests = int(data.get("allowed_requests", 0))
            self.blocked_ads = int(data.get("blocked_ads", 0))
            self.blocked_trackers = int(data.get("blocked_trackers", 0))
            self.bytes_relayed = int(data.get("bytes_relayed", 0))
            self.top_blocked = Counter(data.get("top_blocked", {}))

    def record(self, host: str, action: str, protocol: str, category: str | None = None, rule: str | None = None) -> None:
        should_save = False
        with self._lock:
            self.total_requests += 1
            if action == "blocked":
                self.blocked_requests += 1
                self.top_blocked[host] += 1
                if category == "tracker":
                    self.blocked_trackers += 1
                else:
                    self.blocked_ads += 1
            else:
                self.allowed_requests += 1
            self.recent.appendleft(
                {
                    "at": _utc_now(),
                    "host": host,
                    "action": action,
                    "protocol": protocol,
                    "category": category,
                    "rule": rule,
                }
            )
            self._dirty_events += 1
            should_save = self._dirty_events >= self.save_every
        if should_save:
            self.save()

    def add_bytes(self, amount: int) -> None:
        if amount <= 0:
            return
        with self._lock:
            self.bytes_relayed += amount

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "started_at": self.started_at,
                "total_requests": self.total_requests,
                "blocked_requests": self.blocked_requests,
                "allowed_requests": self.allowed_requests,
                "blocked_ads": self.blocked_ads,
                "blocked_trackers": self.blocked_trackers,
                "bytes_relayed": self.bytes_relayed,
                "top_blocked": self.top_blocked.most_common(20),
                "recent": list(self.recent),
            }

    def save(self) -> None:
        snapshot = self.snapshot()
        with self._lock:
            snapshot["top_blocked"] = dict(self.top_blocked)
        snapshot.pop("recent", None)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.path)
        with self._lock:
            self._dirty_events = 0
