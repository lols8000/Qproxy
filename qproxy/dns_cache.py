"""Caches em memória de alta velocidade para respostas DNS e resolução de hosts.

Reduz a latência de conexões repetidas (sub-milissegundo em cache hit) e
limpa automaticamente quando listas de bloqueio/whitelist são alteradas.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from threading import RLock
from time import monotonic


@dataclass(slots=True)
class CachedDnsRecord:
    payload: bytes
    expires_at: float
    original_ttl: int


class DnsPacketCache:
    """Cache LRU thread-safe de payloads DNS (RFC 1035) indexado por (qname, qtype)."""

    def __init__(
        self,
        max_entries: int = 10_000,
        min_ttl: int = 30,
        max_ttl: int = 3600,
    ) -> None:
        self.max_entries = max(64, int(max_entries))
        self.min_ttl = max(5, int(min_ttl))
        self.max_ttl = max(self.min_ttl, int(max_ttl))
        self._lock = RLock()
        self._entries: OrderedDict[tuple[str, int], CachedDnsRecord] = OrderedDict()
        self.hits = 0
        self.misses = 0

    def get(self, qname: str, qtype: int) -> tuple[bytes, int] | None:
        key = (qname.lower().rstrip("."), int(qtype))
        now = monotonic()
        with self._lock:
            record = self._entries.get(key)
            if record is None:
                self.misses += 1
                return None
            remaining = int(record.expires_at - now)
            if remaining <= 0:
                self._entries.pop(key, None)
                self.misses += 1
                return None
            self._entries.move_to_end(key)
            self.hits += 1
            return record.payload, max(1, remaining)

    def put(self, qname: str, qtype: int, payload: bytes, ttl: int) -> None:
        if not qname or not payload or len(payload) < 12:
            return
        clamped = max(self.min_ttl, min(int(ttl), self.max_ttl))
        key = (qname.lower().rstrip("."), int(qtype))
        record = CachedDnsRecord(
            payload=bytes(payload),
            expires_at=monotonic() + clamped,
            original_ttl=clamped,
        )
        with self._lock:
            self._entries[key] = record
            self._entries.move_to_end(key)
            while len(self._entries) > self.max_entries:
                self._entries.popitem(last=False)

    def invalidate_domain(self, domain: str) -> int:
        target = domain.lower().rstrip(".")
        if not target:
            return 0
        removed = 0
        with self._lock:
            for key in list(self._entries.keys()):
                qname = key[0]
                if qname == target or qname.endswith("." + target):
                    self._entries.pop(key, None)
                    removed += 1
        return removed

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def stats(self) -> dict[str, int | float]:
        with self._lock:
            total = self.hits + self.misses
            rate = round((self.hits / total) * 100.0, 1) if total else 0.0
            return {
                "entries": len(self._entries),
                "max_entries": self.max_entries,
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate_pct": rate,
            }


class HostAddressCache:
    """Cache LRU simples para resultados de getaddrinfo no proxy HTTP/HTTPS."""

    def __init__(self, max_entries: int = 4096, ttl_seconds: float = 120.0) -> None:
        self.max_entries = max(64, int(max_entries))
        self.ttl_seconds = max(5.0, float(ttl_seconds))
        self._lock = RLock()
        self._entries: OrderedDict[tuple[str, int], tuple[list, float]] = OrderedDict()
        self.hits = 0
        self.misses = 0

    def get(self, host: str, port: int) -> list | None:
        key = (host.lower().rstrip("."), int(port))
        now = monotonic()
        with self._lock:
            item = self._entries.get(key)
            if item is None:
                self.misses += 1
                return None
            addresses, expires_at = item
            if now >= expires_at:
                self._entries.pop(key, None)
                self.misses += 1
                return None
            self._entries.move_to_end(key)
            self.hits += 1
            return list(addresses)

    def put(self, host: str, port: int, addresses: list) -> None:
        if not addresses:
            return
        key = (host.lower().rstrip("."), int(port))
        with self._lock:
            self._entries[key] = (list(addresses), monotonic() + self.ttl_seconds)
            self._entries.move_to_end(key)
            while len(self._entries) > self.max_entries:
                self._entries.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
