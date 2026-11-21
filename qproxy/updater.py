from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import gzip
import json
import logging
from pathlib import Path
from threading import Lock
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from .blocklist import count_domain_rules
from .browser_filters import compile_web_rules, compile_youtube_rules
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
    def __init__(
        self, sources: list[RemoteListSource], cache_dir: str | Path, timeout: float = 20.0
    ) -> None:
        self.sources = sources
        self.cache_dir = Path(cache_dir)
        self.timeout = timeout
        self._lock = Lock()
        self.last_results: list[UpdateResult] = []
        self.browser_rules_path = self.cache_dir / "browser_rules.json"
        self._meta_path = self.cache_dir / "etag_cache.json"

    @staticmethod
    def source_path(cache_dir: str | Path, source: RemoteListSource) -> Path:
        filename = source.filename or (source.name.lower().replace(" ", "-") + ".txt")
        return Path(cache_dir) / filename

    def _load_meta(self) -> dict[str, dict[str, str]]:
        if not self._meta_path.is_file():
            return {}
        try:
            data = json.loads(self._meta_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save_meta(self, meta: dict[str, dict[str, str]]) -> None:
        try:
            tmp = self._meta_path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
            tmp.replace(self._meta_path)
        except OSError:
            pass

    def _fetch_one(
        self, source: RemoteListSource, prev_meta: dict[str, str]
    ) -> tuple[UpdateResult, dict[str, str] | None]:
        path = self.source_path(self.cache_dir, source)
        headers = {
            "User-Agent": "Qproxy/4.0 (local packet+dns adblock)",
            "Accept-Encoding": "gzip, identity",
        }
        if path.is_file():
            if prev_meta.get("etag"):
                headers["If-None-Match"] = prev_meta["etag"]
            if prev_meta.get("last_modified"):
                headers["If-Modified-Since"] = prev_meta["last_modified"]
        try:
            req = Request(source.url, headers=headers)
            with urlopen(req, timeout=self.timeout) as response:
                raw_payload = response.read(MAX_LIST_BYTES + 1)
                resp_headers = getattr(response, "headers", None)
            if len(raw_payload) > MAX_LIST_BYTES:
                raise ValueError("tamanho da lista inválido; cache preservado")

            encoding = ""
            if resp_headers is not None:
                encoding = str(resp_headers.get("Content-Encoding", "") or "").lower()
            if "gzip" in encoding or raw_payload[:2] == b"\x1f\x8b":
                payload = gzip.decompress(raw_payload)
            else:
                payload = raw_payload

            if not 128 <= len(payload) <= MAX_LIST_BYTES:
                raise ValueError("tamanho da lista inválido; cache preservado")
            text = payload.decode("utf-8", errors="strict")
            matched = count_domain_rules(text)
            if matched < source.min_rules:
                raise ValueError(
                    f"lista com apenas {matched} regras de domínio válidas; cache preservado"
                )
            if path.exists():
                previous_count = count_domain_rules(
                    path.read_text(encoding="utf-8", errors="ignore")
                )
                if previous_count >= source.min_rules and matched < max(
                    source.min_rules, previous_count // 5
                ):
                    raise ValueError("queda anormal na quantidade de regras; cache preservado")
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_bytes(payload)
            tmp.replace(path)

            new_meta: dict[str, str] = {}
            if resp_headers is not None:
                if resp_headers.get("ETag"):
                    new_meta["etag"] = str(resp_headers.get("ETag"))
                if resp_headers.get("Last-Modified"):
                    new_meta["last_modified"] = str(resp_headers.get("Last-Modified"))

            result = UpdateResult(
                source.name, True, str(path), len(payload), _utc_now(), rules=matched
            )
            LOG.info(
                "Lista %s atualizada: %s regras (%s bytes)", source.name, matched, len(payload)
            )
            return result, new_meta
        except HTTPError as exc:
            if exc.code == 304 and path.is_file():
                cached_text = path.read_text(encoding="utf-8", errors="ignore")
                matched = count_domain_rules(cached_text)
                result = UpdateResult(
                    source.name,
                    True,
                    str(path),
                    bytes=path.stat().st_size,
                    updated_at=_utc_now(),
                    rules=matched,
                    cached=True,
                )
                LOG.info("Lista %s já está atualizada (304 Not Modified, %s regras)", source.name, matched)
                return result, prev_meta
            cache_exists = path.is_file()
            result = UpdateResult(
                source.name,
                False,
                str(path),
                bytes=path.stat().st_size if cache_exists else 0,
                updated_at=(
                    datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()
                    if cache_exists
                    else None
                ),
                error=str(exc),
                cached=cache_exists,
            )
            LOG.warning(
                "Falha ao atualizar %s: %s%s",
                source.name,
                exc,
                " (cache preservado)" if cache_exists else "",
            )
            return result, None
        except Exception as exc:
            cache_exists = path.is_file()
            result = UpdateResult(
                source.name,
                False,
                str(path),
                bytes=path.stat().st_size if cache_exists else 0,
                updated_at=(
                    datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()
                    if cache_exists
                    else None
                ),
                error=str(exc),
                cached=cache_exists,
            )
            LOG.warning(
                "Falha ao atualizar %s: %s%s",
                source.name,
                exc,
                " (cache preservado)" if cache_exists else "",
            )
            return result, None

    def refresh(self) -> list[UpdateResult]:
        # A atualização não apaga nem substitui o cache funcional em caso de erro.
        with self._lock:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            meta = self._load_meta()
            results: list[UpdateResult] = []
            if len(self.sources) <= 1:
                outcomes = [
                    self._fetch_one(source, meta.get(source.name, {})) for source in self.sources
                ]
            else:
                workers = min(4, len(self.sources))
                with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="qproxy-dl") as pool:
                    futures = [
                        (source, pool.submit(self._fetch_one, source, meta.get(source.name, {})))
                        for source in self.sources
                    ]
                    outcomes = [fut.result() for _, fut in futures]

            for source, (result, new_meta) in zip(self.sources, outcomes):
                results.append(result)
                if new_meta:
                    meta[source.name] = new_meta
            if meta:
                self._save_meta(meta)

            self.last_results = results
            try:
                self.build_browser_rules()
            except Exception as exc:
                LOG.warning("Falha ao preparar regras para navegador: %s", exc)
            return list(results)

    def build_browser_rules(self) -> int:
        # O navegador recebe somente regras derivadas das listas verificadas.
        # Atualização atômica impede leitura de JSON truncado.
        yt_sources = [
            self.source_path(self.cache_dir, source)
            for source in self.sources
            if source.name in {"EasyList", "EasyPrivacy", "AdGuard DNS Filter"}
        ]
        if not any(path.is_file() for path in yt_sources):
            return 0
        rules = compile_youtube_rules(yt_sources)
        if not rules:
            return 0
        web_sources = [
            self.source_path(self.cache_dir, source)
            for source in self.sources
            if source.name in {"AdGuard DNS Filter", "EasyList", "EasyPrivacy"}
        ]
        web_rules = compile_web_rules(web_sources)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        temp = self.browser_rules_path.with_suffix(".json.tmp")
        payload: dict[str, object] = {"version": 1, "rules": rules}
        if web_rules:
            payload["web_rules"] = web_rules
        temp.write_text(
            json.dumps(payload, separators=(",", ":")),
            encoding="utf-8",
        )
        temp.replace(self.browser_rules_path)
        LOG.info(
            "Compiladas %d regras YouTube + %d regras globais para navegador",
            len(rules),
            len(web_rules),
        )
        return len(rules)

    def browser_rules(self) -> dict:
        if not self.browser_rules_path.is_file():
            return {"version": 1, "rules": []}
        try:
            payload = json.loads(self.browser_rules_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"version": 1, "rules": []}
        if payload.get("version") != 1 or not isinstance(payload.get("rules"), list):
            return {"version": 1, "rules": []}
        out: dict[str, object] = {"version": 1, "rules": payload["rules"]}
        if isinstance(payload.get("web_rules"), list) and payload["web_rules"]:
            out["web_rules"] = payload["web_rules"]
        return out

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
                    results.append(
                        asdict(
                            UpdateResult(
                                source.name,
                                exists,
                                str(path),
                                bytes=path.stat().st_size if exists else 0,
                                updated_at=(
                                    datetime.fromtimestamp(
                                        path.stat().st_mtime, timezone.utc
                                    ).isoformat()
                                    if exists
                                    else None
                                ),
                                cached=exists,
                                error=None if exists else "Aguardando primeiro download",
                            )
                        )
                    )
            return results
