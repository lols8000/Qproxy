from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any


DEFAULT_REMOTE_BLOCKLISTS = [
    {
        "name": "EasyList",
        "url": "https://easylist.to/easylist/easylist.txt",
        "category": "ad",
        "filename": "easylist.txt",
    },
    {
        "name": "EasyPrivacy",
        "url": "https://easylist.to/easylist/easyprivacy.txt",
        "category": "tracker",
        "filename": "easyprivacy.txt",
    },
]

DEFAULT_COMPATIBILITY_ALLOWLIST = [
    "youtube.com",
    "youtu.be",
    "ytimg.com",
    "googlevideo.com",
    "youtubei.googleapis.com",
    "youtube.googleapis.com",
    "youtube-nocookie.com",
]


@dataclass(slots=True, frozen=True)
class RemoteListSource:
    name: str
    url: str
    category: str = "ad"
    filename: str | None = None

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "RemoteListSource":
        return cls(
            name=str(value["name"]),
            url=str(value["url"]),
            category=str(value.get("category", "ad")),
            filename=(str(value["filename"]) if value.get("filename") else None),
        )


@dataclass(slots=True)
class BrowserCompanionConfig:
    auto_detect: bool = True
    auto_install: bool = True
    package_dir: str = "data/browser"
    managed_policy_install: bool = False

    chrome_extension_id: str | None = None
    chrome_update_url: str = "https://clients2.google.com/service/update2/crx"

    edge_extension_id: str | None = None
    edge_update_url: str = "https://edge.microsoft.com/extensionwebstorebase/v1/crx"

    chromium_extension_id: str | None = None
    chromium_update_url: str = "https://clients2.google.com/service/update2/crx"

    firefox_extension_id: str = "qproxy-youtube@qproxy.local"
    firefox_signed_xpi: str | None = None

    @classmethod
    def from_dict(cls, value: dict[str, Any] | None) -> "BrowserCompanionConfig":
        return cls(**(value or {}))


@dataclass(slots=True)
class Config:
    listen_host: str = "127.0.0.1"
    listen_port: int = 8899
    blocklists: list[str] = field(default_factory=lambda: ["data/blocklist.txt"])
    whitelists: list[str] = field(default_factory=lambda: ["data/whitelist.txt"])
    compatibility_allowlist: list[str] = field(
        default_factory=lambda: list(DEFAULT_COMPATIBILITY_ALLOWLIST)
    )
    connect_timeout_seconds: float = 10.0
    log_allowed: bool = False

    dashboard_enabled: bool = True
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 8900
    dashboard_token: str | None = None

    stats_file: str = "data/stats.json"
    remote_cache_dir: str = "data/remote"
    remote_blocklists: list[RemoteListSource] = field(
        default_factory=lambda: [RemoteListSource.from_dict(v) for v in DEFAULT_REMOTE_BLOCKLISTS]
    )
    update_on_start: bool = True
    update_interval_hours: float = 24.0
    remote_download_timeout_seconds: float = 20.0

    browser_companion: BrowserCompanionConfig = field(default_factory=BrowserCompanionConfig)

    @classmethod
    def load(cls, path: str | Path | None) -> "Config":
        if path is None:
            return cls()
        p = Path(path)
        data = json.loads(p.read_text(encoding="utf-8"))
        if "remote_blocklists" in data:
            data["remote_blocklists"] = [RemoteListSource.from_dict(v) for v in data["remote_blocklists"]]
        if "browser_companion" in data:
            data["browser_companion"] = BrowserCompanionConfig.from_dict(data["browser_companion"])
        return cls(**data)
