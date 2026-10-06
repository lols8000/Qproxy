from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit


def normalize_host(host: str) -> str:
    host = host.strip().lower().rstrip(".")
    if host.startswith("[") and "]" in host:
        return host[1:host.index("]")]
    if ":" in host and host.count(":") == 1:
        host = host.rsplit(":", 1)[0]
    return host


def _domain_from_rule(line: str) -> tuple[str | None, bool]:
    line = line.strip()
    if not line or line.startswith(("#", "!", "[")):
        return None, False

    is_allow = False
    if line.startswith("@@"):
        is_allow = True
        line = line[2:].strip()

    if line.startswith("||"):
        domain = line[2:].split("^", 1)[0].split("/", 1)[0]
        return normalize_host(domain), is_allow

    parts = line.split()
    if len(parts) >= 2 and parts[0] in {"0.0.0.0", "127.0.0.1", "::1"}:
        return normalize_host(parts[1]), is_allow

    if "://" in line:
        parsed = urlsplit(line)
        return normalize_host(parsed.hostname or ""), is_allow

    if any(ch in line for ch in "/$*?="):
        return None, is_allow

    return normalize_host(line), is_allow


class DomainMatcher:
    def __init__(self) -> None:
        self.blocked: set[str] = set()
        self.allowed: set[str] = set()

    def add_block(self, domain: str) -> None:
        domain = normalize_host(domain)
        if domain:
            self.blocked.add(domain)

    def add_allow(self, domain: str) -> None:
        domain = normalize_host(domain)
        if domain:
            self.allowed.add(domain)

    def load_file(self, path: str | Path, default_allow: bool = False) -> int:
        p = Path(path)
        if not p.exists():
            return 0
        count = 0
        for raw in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            domain, rule_allow = _domain_from_rule(raw)
            if not domain:
                continue
            allow = default_allow or rule_allow
            (self.add_allow if allow else self.add_block)(domain)
            count += 1
        return count

    @staticmethod
    def _suffixes(host: str):
        labels = normalize_host(host).split(".")
        for i in range(len(labels)):
            yield ".".join(labels[i:])

    def is_allowed(self, host: str) -> bool:
        return any(suffix in self.allowed for suffix in self._suffixes(host))

    def is_blocked(self, host: str) -> bool:
        host = normalize_host(host)
        if not host or self.is_allowed(host):
            return False
        return any(suffix in self.blocked for suffix in self._suffixes(host))
