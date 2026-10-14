from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import logging
from pathlib import Path
from threading import Lock
from urllib.request import Request, urlopen

from .blocklist import count_domain_rules
from .config import RemoteListSource

LOG = logging.getLogger("qproxy")
MAX_LIST_BYTES = 25 * 1024 * 1024


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class UpdateResult:
    name: str
    ok: bool
    path: str
    bytes: int = 0
    updated_at: str | None = None
    error: str | None = None
    rules: int = 0
    cached: bool = False


class BlocklistUpdater:
    def __init__(self, sources: list[RemoteListSource], cache_dir: str | Path, timeout: float = 20.0) -> None:
        self.sources = sources
        self.cache_dir = Path(cache_dir)
        self.timeout = timeout
        self._lock = Lock()
        self.last_results: list[UpdateResult] = []

    @staticmethod
    def source_path(cache_dir: str | Path, source: RemoteListSource) -> Path:
        filename = source.filename or (source.name.lower().replace(" ", "-") + ".txt")
        return Path(cache_dir) / filename

    def refresh(self) -> list[UpdateResult]:
        # A atualização não apaga nem substitui o cache funcional em caso de erro.
        with self._lock:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            results: list[UpdateResult] = []
            for source in self.sources:
                path = self.source_path(self.cache_dir, source)
                try:
                    req = Request(source.url, headers={"User-Agent": "Qproxy/0.3.5 (local adblock proxy)"})
                    with urlopen(req, timeout=self.timeout) as response:
                        payload = response.read(MAX_LIST_BYTES + 1)
                    if not 128 <= len(payload) <= MAX_LIST_BYTES:
                        raise ValueError("tamanho da lista inválido; cache preservado")
                    text = payload.decode("utf-8", errors="strict")
                    matched = count_domain_rules(text)
                    if matched < source.min_rules:
                        raise ValueError(f"lista com apenas {matched} regras de domínio válidas; cache preservado")
                    if path.exists():
                        previous_count = count_domain_rules(
                            path.read_text(encoding="utf-8", errors="ignore")
                        )
                        if previous_count >= source.min_rules and matched < max(source.min_rules, previous_count // 5):
                            raise ValueError("queda anormal na quantidade de regras; cache preservado")
                    tmp = path.with_suffix(path.suffix + ".tmp")
                    tmp.write_bytes(payload)
                    tmp.replace(path)
                    result = UpdateResult(source.name, True, str(path), len(payload), _utc_now(), rules=matched)
                    LOG.info("Lista %s atualizada: %s regras (%s bytes)", source.name, matched, len(payload))
                except Exception as exc:
                    cache_exists = path.is_file()
                    result = UpdateResult(
                        source.name, False, str(path),
                        bytes=path.stat().st_size if cache_exists else 0,
                        updated_at=datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat() if cache_exists else None,
                        error=str(exc),
                        cached=cache_exists,
                    )
                    LOG.warning("Falha ao atualizar %s: %s%s", source.name, exc, " (cache preservado)" if cache_exists else "")
                results.append(result)
            self.last_results = results
            return list(results)

    def status(self) -> list[dict]:
        with self._lock:
            observed = {result.name: result for result in self.last_results}
            results: list[dict] = []
            for source in self.sources:
                path = self.source_path(self.cache_dir, source)
                if source.name in observed:
                    results.append(asdict(observed[source.name]))
                else:
                    exists = path.is_file()
                    results.append(asdict(UpdateResult(
                        source.name, exists, str(path),
                        bytes=path.stat().st_size if exists else 0,
                        updated_at=datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat() if exists else None,
                        cached=exists,
                        error=None if exists else "Aguardando primeiro download",
                    )))
            return results
