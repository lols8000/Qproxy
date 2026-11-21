from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any


HAGEZI_PRO = {
    "name": "HaGeZi Multi PRO",
    "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt",
    "category": "ad",
    "filename": "hagezi-pro.txt",
    "min_rules": 5000,
}

ADGUARD_DNS_FILTER = {
    "name": "AdGuard DNS Filter",
    "url": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
    "category": "ad",
    "filename": "adguard-dns.txt",
    "min_rules": 2000,
}

OISD_BIG = {
    "name": "OISD Big",
    "url": "https://big.oisd.nl/",
    "category": "ad",
    "filename": "oisd-big.txt",
    "min_rules": 5000,
}

HAGEZI_WINOFFICE = {
    "name": "HaGeZi Windows Telemetry",
    "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/native.winoffice.txt",
    "category": "tracker",
    "filename": "hagezi-winoffice.txt",
    "min_rules": 50,
}

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

STEVENBLACK_HOSTS = {
    "name": "StevenBlack hosts",
    "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "category": "ad",
    "filename": "stevenblack-hosts.txt",
    "min_rules": 2000,
}

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
    min_rules: int = 10

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "RemoteListSource":
        return cls(
            name=str(value["name"]),
            url=str(value["url"]),
            category=str(value.get("category", "ad")),
            filename=(str(value["filename"]) if value.get("filename") else None),
            min_rules=int(value.get("min_rules", 10)),
        )


@dataclass(slots=True)
class PacketFilterConfig:
    enabled: bool = True
    windivert_dir: str = "data/windivert"
    auto_download_windivert: bool = False
    filter_dns: bool = True
    filter_cname_cloaking: bool = True
    filter_tls_sni: bool = True
    filter_quic_sni: bool = True
    filter_http: bool = True
    signal_local_dns_filter: bool = True
    block_dot: bool = False
    dns_block_mode: str = "zero_ip"
    dns_cache_enabled: bool = True
    dns_cache_max_entries: int = 10_000
    dns_cache_min_ttl: int = 30
    dns_cache_max_ttl: int = 3600
    flush_windows_dns_on_start: bool = True

    @classmethod
    def from_dict(cls, value: dict[str, Any] | None) -> "PacketFilterConfig":
        raw = dict(value or {})
        valid = {k: v for k, v in raw.items() if k in cls.__dataclass_fields__}
        return cls(**valid)


@dataclass(slots=True)
class DnsServerConfig:
    enabled: bool = False
    listen_host: str = "127.0.0.1"
    listen_port: int = 53
    upstreams: list[str] = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8", "9.9.9.9"])
    upstream_timeout_seconds: float = 2.0

    @classmethod
    def from_dict(cls, value: dict[str, Any] | None) -> "DnsServerConfig":
        raw = dict(value or {})
        valid = {k: v for k, v in raw.items() if k in cls.__dataclass_fields__}
        return cls(**valid)


@dataclass(slots=True)
class BrowserCompanionConfig:
    auto_detect: bool = True
    auto_install: bool = True
    package_dir: str = "data/browser"

    # Só grava políticas do navegador quando existe um artefato/ID
    # de distribuição válido para aquele navegador.
    managed_policy_install: bool = True

    chrome_extension_id: str | None = None
    chrome_update_url: str = "https://clients2.google.com/service/update2/crx"

    edge_extension_id: str | None = None
    edge_update_url: str = "https://edge.microsoft.com/extensionwebstorebase/v1/crx"

    brave_extension_id: str | None = None
    brave_update_url: str = "https://clients2.google.com/service/update2/crx"

    firefox_extension_id: str = "qproxy-youtube@qproxy.local"
    firefox_signed_xpi: str | None = None

    # Campos mantidos somente para não quebrar configurações V3.1.
    chromium_extension_id: str | None = None
    chromium_update_url: str = "https://clients2.google.com/service/update2/crx"

    @classmethod
    def from_dict(cls, value: dict[str, Any] | None) -> "BrowserCompanionConfig":
        return cls(**(value or {}))


@dataclass(slots=True)
class Config:
    mode: str = "auto"  # auto | packet | dns | proxy | hybrid
    listen_host: str = "127.0.0.1"
    listen_port: int = 8899
    blocklists: list[str] = field(default_factory=lambda: ["data/blocklist.txt"])
    whitelists: list[str] = field(default_factory=lambda: ["data/whitelist.txt"])
    manual_blocklist_file: str = "data/manual_blocklist.txt"
    compatibility_allowlist: list[str] = field(
        default_factory=lambda: list(DEFAULT_COMPATIBILITY_ALLOWLIST)
    )
    connect_timeout_seconds: float = 10.0
    happy_eyeballs_delay_seconds: float = 0.25
    log_allowed: bool = False

    dashboard_enabled: bool = True
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 8900
    dashboard_token: str | None = None

    stats_file: str = "data/stats.json"
    remote_cache_dir: str = "data/remote"
    remote_blocklists: list[RemoteListSource] = field(
        default_factory=lambda: [
            RemoteListSource.from_dict(v)
            for v in [
                HAGEZI_PRO,
                ADGUARD_DNS_FILTER,
                OISD_BIG,
                STEVENBLACK_HOSTS,
                HAGEZI_WINOFFICE,
                *DEFAULT_REMOTE_BLOCKLISTS,
            ]
        ]
    )
    update_on_start: bool = True
    update_interval_hours: float = 6.0
    remote_download_timeout_seconds: float = 20.0

    packet_filter: PacketFilterConfig = field(default_factory=PacketFilterConfig)
    dns_server: DnsServerConfig = field(default_factory=DnsServerConfig)
    browser_companion: BrowserCompanionConfig = field(default_factory=BrowserCompanionConfig)

    @classmethod
    def load(cls, path: str | Path | None) -> "Config":
        if path is None:
            return cls()

        p = Path(path)
        data = json.loads(p.read_text(encoding="utf-8"))

        if "remote_blocklists" in data:
            data["remote_blocklists"] = [
                RemoteListSource.from_dict(v) for v in data["remote_blocklists"]
            ]

        if "browser_companion" in data:
            data["browser_companion"] = BrowserCompanionConfig.from_dict(data["browser_companion"])

        if "packet_filter" in data:
            data["packet_filter"] = PacketFilterConfig.from_dict(data["packet_filter"])

        if "dns_server" in data:
            data["dns_server"] = DnsServerConfig.from_dict(data["dns_server"])

        valid = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**valid)
