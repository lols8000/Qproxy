from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path


@dataclass(slots=True)
class Config:
    listen_host: str = "127.0.0.1"
    listen_port: int = 8899
    blocklists: list[str] = field(default_factory=lambda: ["data/blocklist.txt"])
    whitelists: list[str] = field(default_factory=lambda: ["data/whitelist.txt"])
    connect_timeout_seconds: float = 10.0
    log_allowed: bool = False

    @classmethod
    def load(cls, path: str | Path | None) -> "Config":
        if path is None:
            return cls()
        p = Path(path)
        data = json.loads(p.read_text(encoding="utf-8"))
        return cls(**data)
