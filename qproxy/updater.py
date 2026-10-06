from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import logging
from pathlib import Path
from threading import Lock
from urllib.request import Request, urlopen

from .config import RemoteListSource

LOG = logging.getLogger("qproxy")


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
        if not self._lock.acquire(blocking=False):
            return self.last_results
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            results: list[UpdateResult] = []
            for source in self.sources:
                path = self.source_path(self.cache_dir, source)
                try:
                    req = Request(source.url, headers={"User-Agent": "Qproxy/0.2 (+local adblock proxy)"})
                    with urlopen(req, timeout=self.timeout) as response:
                        payload = response.read()
                    if len(payload) < 128:
                        raise ValueError("lista remota pequena demais; atualização descartada")
                    payload.decode("utf-8", errors="strict")
                    tmp = path.with_suffix(path.suffix + ".tmp")
                    tmp.write_bytes(payload)
                    tmp.replace(path)
                    result = UpdateResult(source.name, True, str(path), len(payload), _utc_now())
                    LOG.info("Lista %s atualizada (%d bytes)", source.name, len(payload))
                except Exception as exc:
                    result = UpdateResult(source.name, False, str(path), error=str(exc))
                    LOG.warning("Falha ao atualizar %s: %s", source.name, exc)
                results.append(result)
            self.last_results = results
            return results
        finally:
            self._lock.release()

    def status(self) -> list[dict]:
        return [asdict(result) for result in self.last_results]
