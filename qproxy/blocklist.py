from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from time import monotonic


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
        # Somente regras globais por domínio: não amplie filtros de URL,
        # recursos ou condições para o domínio inteiro.
        candidate = line[2:]
        if candidate.endswith("^"):
            candidate = candidate[:-1]
        candidate = candidate.lower().rstrip(".")
        return (candidate if _hostname_like(candidate) else None), is_allow

    parts = line.split()
    if len(parts) >= 2 and parts[0] in {"0.0.0.0", "127.0.0.1", "::1"}:
        domain = normalize_host(parts[1])
        return (domain if _hostname_like(domain) else None), is_allow

    if "://" in line or any(ch in line for ch in "/$*?=#@,:|^"):
        return None, is_allow

    domain = line.lower().rstrip(".")
    return (domain if _hostname_like(domain) else None), is_allow


def count_domain_rules(payload: str) -> int:
    """Contagem de regras reconhecíveis; usada para rejeitar listas inválidas."""
    return sum(1 for line in payload.splitlines() if _domain_from_rule(line)[0])


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
        self.origins: dict[str, str] = {}

    def add_block(self, domain: str, category: str = "ad", origin: str = "local") -> None:
        domain = normalize_host(domain)
        if domain and _hostname_like(domain):
            self.blocked.add(domain)
            if category == "tracker" or domain not in self.categories:
                self.categories[domain] = category
            self.origins.setdefault(domain, origin)

    def add_allow(self, domain: str) -> None:
        domain = normalize_host(domain)
        if domain and _hostname_like(domain):
            self.allowed.add(domain)

    def remove_allow(self, domain: str) -> None:
        self.allowed.discard(normalize_host(domain))

    def load_file(
        self, path: str | Path, default_allow: bool = False,
        category: str = "ad", origin: str | None = None,
    ) -> int:
        p = Path(path)
        if not p.exists():
            return 0
        count = 0
        for raw in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            domain, rule_allow = _domain_from_rule(raw)
            if not domain:
                continue
            if default_allow or rule_allow:
                self.add_allow(domain)
            else:
                self.add_block(domain, category=category, origin=origin or p.name)
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
    """Regras atualizadas atomicamente, com bloqueios manuais persistentes."""

    def __init__(
        self,
        block_sources: list[tuple[Path, str]],
        whitelist_paths: list[Path],
        static_allowlist: list[str] | None = None,
        manual_blocklist_path: Path | None = None,
    ) -> None:
        self.block_sources = block_sources
        self.whitelist_paths = whitelist_paths
        self.manual_blocklist_path = Path(manual_blocklist_path) if manual_blocklist_path else None
        self.static_allowlist = tuple(
            domain
            for raw in (static_allowlist or [])
            if (domain := normalize_host(raw)) and _hostname_like(domain)
        )
        self._lock = RLock()
        # Serializa edições e recargas sem prender consultas ao matcher.
        self._reload_lock = RLock()
        self._paused_until = 0.0
        self._matcher = DomainMatcher()
        self._manual_blocks: set[str] = set()
        self._user_whitelist: set[str] = set()
        self._ordered_blocks: tuple[str, ...] = ()
        self.last_load_counts = {"blocked_rules": 0, "allow_rules": 0}
        self.reload()

    @staticmethod
    def _read_domains(path: Path | None) -> set[str]:
        if path is None or not path.is_file():
            return set()
        domains: set[str] = set()
        for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            domain, _ = _domain_from_rule(raw)
            if domain:
                domains.add(domain)
        return domains

    @staticmethod
    def _save_domains(path: Path, domains: set[str]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_name(path.name + ".tmp")
        temp.write_text("".join(f"{domain}\n" for domain in sorted(domains)), encoding="utf-8")
        temp.replace(path)

    def reload(self) -> dict[str, int]:
        # O matcher antigo continua atendendo conexões enquanto a nova
        # lista é construída. Só o swap final exige lock dos leitores.
        with self._reload_lock:
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

            user_whitelist = self._read_domains(self.whitelist_paths[0]) if self.whitelist_paths else set()
            manual_blocks = self._read_domains(self.manual_blocklist_path)
            for domain in manual_blocks:
                matcher.add_block(domain, category="manual", origin="Você")
            ordered = tuple(sorted(matcher.blocked))
            counts = {
                "blocked_rules": blocked + len(manual_blocks),
                "allow_rules": allowed,
                "blocked_domains": len(matcher.blocked),
                "allowed_domains": len(matcher.allowed),
                "manual_domains": len(manual_blocks),
                "compatibility_domains": len(self.static_allowlist),
            }
            with self._lock:
                self._matcher = matcher
                self._manual_blocks = manual_blocks
                self._user_whitelist = user_whitelist
                self._ordered_blocks = ordered
                self.last_load_counts = counts
            return dict(counts)

    def _protected(self, host: str) -> bool:
        return any(
            host == safe or host.endswith("." + safe)
            for safe in self.static_allowlist
        )

    def evaluate(self, host: str) -> MatchResult:
        host = normalize_host(host)
        with self._lock:
            matcher = self._matcher
            paused = monotonic() < self._paused_until
            manual = self._manual_blocks
            whitelist = self._user_whitelist
        if paused:
            return MatchResult(False, host, rule="paused", whitelisted=True)

        suffixes = tuple(DomainMatcher._suffixes(host))
        for suffix in suffixes:
            if suffix in whitelist or suffix in self.static_allowlist:
                return MatchResult(False, host, rule=suffix, whitelisted=True)
        # Bloqueio escolhido pelo usuário vence exceção de listas remotas.
        for suffix in suffixes:
            if suffix in manual:
                return MatchResult(True, host, rule=suffix, category="manual")
        return matcher.evaluate(host)

    def pause_for(self, seconds: int = 600) -> None:
        if not 1 <= seconds <= 600:
            raise ValueError("Pausa deve ter entre 1 e 600 segundos")
        with self._lock:
            self._paused_until = monotonic() + seconds

    def resume(self) -> None:
        with self._lock:
            self._paused_until = 0.0

    def is_blocked(self, host: str) -> bool:
        return self.evaluate(host).blocked

    def add_to_blocklist(self, domain: str) -> str:
        domain = normalize_host(domain)
        if not _hostname_like(domain):
            raise ValueError("Informe apenas o domínio, sem URL ou caminho (ex.: ads.exemplo.com)")
        if self.manual_blocklist_path is None:
            raise RuntimeError("Arquivo de bloqueios manuais não configurado")
        with self._reload_lock:
            if self._protected(domain):
                raise ValueError("Domínio protegido para não interromper vídeos ou navegação")
            if any(domain == d or domain.endswith("." + d) for d in self._user_whitelist):
                raise ValueError("Domínio liberado manualmente; retire-o da whitelist primeiro")
            domains = set(self._manual_blocks)
            domains.add(domain)
            self._save_domains(self.manual_blocklist_path, domains)
            self.reload()
        return domain

    def remove_from_blocklist(self, domain: str) -> str:
        domain = normalize_host(domain)
        with self._reload_lock:
            if self.manual_blocklist_path is None:
                raise RuntimeError("Arquivo de bloqueios manuais não configurado")
            domains = set(self._manual_blocks)
            domains.discard(domain)
            self._save_domains(self.manual_blocklist_path, domains)
            self.reload()
        return domain

    def add_to_whitelist(self, domain: str) -> str:
        domain = normalize_host(domain)
        if not _hostname_like(domain):
            raise ValueError("Domínio inválido")
        if not self.whitelist_paths:
            raise RuntimeError("Nenhum arquivo de whitelist configurado")
        with self._reload_lock:
            path = self.whitelist_paths[0]
            domains = self._read_domains(path)
            domains.add(domain)
            self._save_domains(path, domains)
            self.reload()
        return domain

    def remove_from_whitelist(self, domain: str) -> str:
        domain = normalize_host(domain)
        if not self.whitelist_paths:
            raise RuntimeError("Nenhum arquivo de whitelist configurado")
        with self._reload_lock:
            path = self.whitelist_paths[0]
            domains = self._read_domains(path)
            domains.discard(domain)
            self._save_domains(path, domains)
            self.reload()
        return domain

    def list_rules(self, query: str = "", scope: str = "all", page: int = 1, limit: int = 40) -> dict:
        query = query.strip().lower()
        if len(query) > 253 or any(ch in query for ch in "\r\n"):
            raise ValueError("Busca inválida")
        if scope not in {"all", "manual"} or page < 1 or page > 100000 or not 1 <= limit <= 100:
            raise ValueError("Parâmetros de listagem inválidos")
        with self._lock:
            matcher = self._matcher
            manual = self._manual_blocks
            domains = tuple(sorted(manual)) if scope == "manual" else self._ordered_blocks
        filtered = (domain for domain in domains if query in domain)
        start = (page - 1) * limit
        total = 0
        items = []
        for domain in filtered:
            if start <= total < start + limit:
                items.append({
                    "domain": domain,
                    "category": "manual" if domain in manual else matcher.categories.get(domain, "ad"),
                    "source": "Você" if domain in manual else matcher.origins.get(domain, "local"),
                    "manual": domain in manual,
                    "whitelisted": domain in matcher.allowed,
                })
            total += 1
        return {"total": total, "page": page, "limit": limit, "items": items}

    def snapshot(self) -> dict:
        with self._lock:
            matcher = self._matcher
            counts = dict(self.last_load_counts)
            remaining = max(0, int(self._paused_until - monotonic()))
            whitelist = sorted(self._user_whitelist)
            manual = sorted(self._manual_blocks)
        counts["whitelist"] = whitelist
        counts["manual_blocklist"] = manual
        counts["blocking_paused"] = remaining > 0
        counts["pause_remaining_seconds"] = remaining
        counts["compatibility_allowlist"] = list(self.static_allowlist)
        return counts
