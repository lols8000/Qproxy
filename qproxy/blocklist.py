from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from threading import RLock


def normalize_host(host: str) -> str:
    host = host.strip().lower().rstrip(".")
    if host.startswith("[") and "]" in host:
        return host[1:host.index("]")]
    if ":" in host and host.count(":") == 1:
        host = host.rsplit(":", 1)[0]
    return host


def _hostname_like(value: str) -> bool:
    if not value or len(value) > 253 or any(ch in value for ch in " *?/#@=,$"):
        return False
    labels = value.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
            return False
        if not all(ch.isalnum() or ch == "-" for ch in label):
            return False
    return True


def _domain_from_rule(line: str) -> tuple[str | None, bool]:
    line = line.strip()
    if not line or line.startswith(("#", "!", "[")):
        return None, False
    if any(marker in line for marker in ("##", "#@#", "#?#", "#$#", "#%#")):
        return None, False

    is_allow = False
    if line.startswith("@@"):
        is_allow = True
        line = line[2:].strip()

    if line.startswith("||"):
        # Regras EasyList que usam caminhos, modificadores ($image, $script,
        # $third-party, $domain etc.) ou padrões não podem virar bloqueio
        # do domínio inteiro: isso quebra imagens, vídeos e aplicações.
        candidate = line[2:]
        if candidate.endswith("^"):
            candidate = candidate[:-1]
        candidate = candidate.lower().rstrip(".")
        return (candidate if _hostname_like(candidate) else None), is_allow

    parts = line.split()
    if len(parts) >= 2 and parts[0] in {"0.0.0.0", "127.0.0.1", "::1"}:
        domain = normalize_host(parts[1])
        return (domain if _hostname_like(domain) else None), is_allow

    # URLs completas são sempre dependentes de caminho/esquema:
    # converter https://site/imagem em bloqueio de site inteiro é inseguro.
    if "://" in line:
        return None, is_allow

    if any(ch in line for ch in "/$*?=#@,:|^"):
        return None, is_allow

    domain = line.lower().rstrip(".")
    return (domain if _hostname_like(domain) else None), is_allow


@dataclass(frozen=True, slots=True)
class MatchResult:
    blocked: bool
    host: str
    rule: str | None = None
    category: str | None = None
    whitelisted: bool = False


class DomainMatcher:
    def __init__(self) -> None:
        self.blocked: set[str] = set()
        self.allowed: set[str] = set()
        self.categories: dict[str, str] = {}

    def add_block(self, domain: str, category: str = "ad") -> None:
        domain = normalize_host(domain)
        if domain and _hostname_like(domain):
            self.blocked.add(domain)
            if category == "tracker" or domain not in self.categories:
                self.categories[domain] = category

    def add_allow(self, domain: str) -> None:
        domain = normalize_host(domain)
        if domain and _hostname_like(domain):
            self.allowed.add(domain)

    def remove_allow(self, domain: str) -> None:
        self.allowed.discard(normalize_host(domain))

    def load_file(self, path: str | Path, default_allow: bool = False, category: str = "ad") -> int:
        p = Path(path)
        if not p.exists():
            return 0
        count = 0
        for raw in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            domain, rule_allow = _domain_from_rule(raw)
            if not domain:
                continue
            allow = default_allow or rule_allow
            if allow:
                self.add_allow(domain)
            else:
                self.add_block(domain, category=category)
            count += 1
        return count

    @staticmethod
    def _suffixes(host: str):
        labels = normalize_host(host).split(".")
        for i in range(len(labels)):
            yield ".".join(labels[i:])

    def evaluate(self, host: str) -> MatchResult:
        host = normalize_host(host)
        if not host:
            return MatchResult(False, host)
        for suffix in self._suffixes(host):
            if suffix in self.allowed:
                return MatchResult(False, host, rule=suffix, whitelisted=True)
        for suffix in self._suffixes(host):
            if suffix in self.blocked:
                return MatchResult(True, host, rule=suffix, category=self.categories.get(suffix, "ad"))
        return MatchResult(False, host)

    def is_allowed(self, host: str) -> bool:
        return self.evaluate(host).whitelisted

    def is_blocked(self, host: str) -> bool:
        return self.evaluate(host).blocked


class RuleManager:
    """Atomically reloadable domain rules shared by proxy and dashboard."""

    def __init__(
        self,
        block_sources: list[tuple[Path, str]],
        whitelist_paths: list[Path],
        static_allowlist: list[str] | None = None,
    ) -> None:
        self.block_sources = block_sources
        self.whitelist_paths = whitelist_paths
        self.static_allowlist = tuple(
            domain
            for raw in (static_allowlist or [])
            if (domain := normalize_host(raw)) and _hostname_like(domain)
        )
        self._lock = RLock()
        self._matcher = DomainMatcher()
        self.last_load_counts = {"blocked_rules": 0, "allow_rules": 0}
        self.reload()

    def reload(self) -> dict[str, int]:
        matcher = DomainMatcher()
        blocked = 0
        allowed = 0

        for path, category in self.block_sources:
            blocked += matcher.load_file(path, category=category)

        for domain in self.static_allowlist:
            matcher.add_allow(domain)
            allowed += 1

        for path in self.whitelist_paths:
            allowed += matcher.load_file(path, default_allow=True)

        with self._lock:
            self._matcher = matcher
            self.last_load_counts = {
                "blocked_rules": blocked,
                "allow_rules": allowed,
                "blocked_domains": len(matcher.blocked),
                "allowed_domains": len(matcher.allowed),
                "compatibility_domains": len(self.static_allowlist),
            }
            return dict(self.last_load_counts)

    def evaluate(self, host: str) -> MatchResult:
        with self._lock:
            matcher = self._matcher
        return matcher.evaluate(host)

    def is_blocked(self, host: str) -> bool:
        return self.evaluate(host).blocked

    def add_to_whitelist(self, domain: str) -> str:
        domain = normalize_host(domain)
        if not _hostname_like(domain):
            raise ValueError("Domínio inválido")
        if not self.whitelist_paths:
            raise RuntimeError("Nenhum arquivo de whitelist configurado")
        path = self.whitelist_paths[0]
        path.parent.mkdir(parents=True, exist_ok=True)
        existing = set()
        if path.exists():
            existing = {
                normalize_host(line)
                for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
                if line.strip() and not line.startswith("#")
            }
        if domain not in existing:
            with path.open("a", encoding="utf-8") as file:
                if path.stat().st_size:
                    file.write("\n")
                file.write(domain)
        self.reload()
        return domain

    def remove_from_whitelist(self, domain: str) -> str:
        domain = normalize_host(domain)
        if not self.whitelist_paths:
            raise RuntimeError("Nenhum arquivo de whitelist configurado")
        path = self.whitelist_paths[0]
        if path.exists():
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            kept = [line for line in lines if normalize_host(line) != domain]
            path.write_text("\n".join(kept).rstrip() + ("\n" if kept else ""), encoding="utf-8")
        self.reload()
        return domain

    def snapshot(self) -> dict:
        with self._lock:
            matcher = self._matcher
            counts = dict(self.last_load_counts)
            allowed = sorted(matcher.allowed)
        counts["whitelist"] = allowed
        counts["compatibility_allowlist"] = list(self.static_allowlist)
        return counts
