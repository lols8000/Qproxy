"""Servidor DNS local assíncrono de alta velocidade com cache LRU e corrida de upstreams.

Usado no modo `dns` ou como fallback automático quando o driver WinDivert não
está instalado, mantendo bloqueio de anúncios, CNAME cloaking e aceleração
via cache DNS para todos os aplicativos do Windows sem passar tráfego por proxy.
"""
from __future__ import annotations

import asyncio
import logging
import struct

from .blocklist import RuleManager
from .config import DnsServerConfig
from .dns_cache import DnsPacketCache
from .packet_parser import (
    build_dns_blocked_from_response,
    build_dns_blocked_payload,
    parse_dns_query,
    parse_dns_response,
    rewrite_dns_cached_payload,
)
from .stats import StatsStore

LOG = logging.getLogger("qproxy")
DOH_CANARY_DOMAIN = "use-application-dns.net"


class _UpstreamUdpClient(asyncio.DatagramProtocol):
    def __init__(self, future: asyncio.Future[bytes]) -> None:
        self.future = future

    def datagram_received(self, data: bytes, addr) -> None:
        if not self.future.done():
            self.future.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self.future.done():
            self.future.set_exception(exc)


async def _query_single_upstream(
    loop: asyncio.AbstractEventLoop,
    host: str,
    port: int,
    payload: bytes,
    timeout: float,
) -> bytes:
    fut: asyncio.Future[bytes] = loop.create_future()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: _UpstreamUdpClient(fut),
        remote_addr=(host, port),
    )
    try:
        transport.sendto(payload)
        return await asyncio.wait_for(fut, timeout=timeout)
    finally:
        transport.close()


class _LocalDnsUdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, server: "LocalDnsServer") -> None:
        self.server = server
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr) -> None:
        asyncio.create_task(self._handle(data, addr))

    async def _handle(self, data: bytes, addr) -> None:
        try:
            response = await self.server.resolve_payload(data)
            if response and self.transport is not None and not self.transport.is_closing():
                self.transport.sendto(response, addr)
        except Exception as exc:
            LOG.debug("Erro ao responder consulta DNS UDP de %s: %r", addr, exc)


class LocalDnsServer:
    """Servidor DNS local UDP/TCP com bloqueio, CNAME cloaking, cache LRU e corrida de upstreams."""

    def __init__(
        self,
        cfg: DnsServerConfig,
        rules: RuleManager,
        stats: StatsStore,
        dns_cache: DnsPacketCache,
        block_mode: str = "zero_ip",
        filter_cname_cloaking: bool = True,
        signal_local_dns_filter: bool = True,
    ) -> None:
        self.cfg = cfg
        self.rules = rules
        self.stats = stats
        self.dns_cache = dns_cache
        self.block_mode = block_mode
        self.filter_cname_cloaking = filter_cname_cloaking
        self.signal_local_dns_filter = signal_local_dns_filter
        self._udp_transport: asyncio.DatagramTransport | None = None
        self._udp_v6_transport: asyncio.DatagramTransport | None = None
        self._tcp_server: asyncio.AbstractServer | None = None
        self.bound_port: int = cfg.listen_port
        self.running = False

    def _parse_upstream(self, value: str) -> tuple[str, int]:
        if ":" in value and value.count(":") == 1:
            h, p = value.rsplit(":", 1)
            if p.isdigit():
                return h.strip(), int(p)
        return value.strip(), 53

    async def _forward_racing(self, payload: bytes) -> bytes | None:
        loop = asyncio.get_running_loop()
        upstreams = [self._parse_upstream(u) for u in self.cfg.upstreams if u.strip()]
        if not upstreams:
            upstreams = [("1.1.1.1", 53), ("8.8.8.8", 53)]
        tasks = [
            asyncio.create_task(
                _query_single_upstream(loop, host, port, payload, self.cfg.upstream_timeout_seconds)
            )
            for host, port in upstreams
        ]
        try:
            pending = set(tasks)
            while pending:
                done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    if task.cancelled():
                        continue
                    exc = task.exception()
                    if exc is None:
                        result = task.result()
                        if result and len(result) >= 12:
                            return result
            return None
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def resolve_payload(self, query_payload: bytes) -> bytes | None:
        query = parse_dns_query(query_payload)
        if query is None:
            return None

        if not self.rules.is_paused():
            if self.signal_local_dns_filter and query.qname == DOH_CANARY_DOMAIN:
                return build_dns_blocked_payload(query_payload, mode="nxdomain", ttl=60)

            decision = self.rules.evaluate(query.qname)
            if decision.blocked:
                self.stats.record(query.qname, "blocked", "dns", decision.category, decision.rule)
                LOG.info("BLOCK DNS-LOCAL %s [%s]", query.qname, decision.category or "ad")
                return build_dns_blocked_payload(query_payload, mode=self.block_mode, ttl=60)

            cached = self.dns_cache.get(query.qname, query.qtype)
            if cached is not None:
                cached_payload, remaining_ttl = cached
                self.stats.record_dns_cache(hit=True)
                return rewrite_dns_cached_payload(cached_payload, query.txid, remaining_ttl)
            self.stats.record_dns_cache(hit=False)

        response = await self._forward_racing(query_payload)
        if response is None:
            return None

        parsed_resp = parse_dns_response(response)
        if parsed_resp is not None and not self.rules.is_paused():
            if (
                self.filter_cname_cloaking
                and parsed_resp.cnames
                and not self.rules.is_whitelisted(query.qname)
            ):
                for cname in parsed_resp.cnames:
                    cname_dec = self.rules.evaluate(cname)
                    if cname_dec.blocked:
                        rule_name = f"cname:{cname_dec.rule or cname}"
                        self.stats.record(
                            query.qname,
                            "blocked",
                            "cname",
                            cname_dec.category or "tracker",
                            rule_name,
                        )
                        LOG.info("BLOCK CNAME-LOCAL %s -> %s", query.qname, cname)
                        return build_dns_blocked_from_response(
                            response, mode=self.block_mode, ttl=60
                        )

            if parsed_resp.rcode == 0 and parsed_resp.answer_count > 0:
                self.dns_cache.put(query.qname, query.qtype, response, parsed_resp.min_ttl)

        self.stats.record(query.qname, "allowed", "dns")
        return response

    async def _handle_tcp_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            length_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=4)
            msg_len = struct.unpack("!H", length_bytes)[0]
            if not 12 <= msg_len <= 4096:
                return
            payload = await asyncio.wait_for(reader.readexactly(msg_len), timeout=4)
            response = await self.resolve_payload(payload)
            if response:
                writer.write(struct.pack("!H", len(response)) + response)
                await writer.drain()
        except Exception:
            pass
        finally:
            if not writer.is_closing():
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _LocalDnsUdpProtocol(self),
            local_addr=(self.cfg.listen_host, self.cfg.listen_port),
        )
        self._udp_transport = transport
        sockname = transport.get_extra_info("sockname")
        if sockname:
            self.bound_port = int(sockname[1])

        if self.cfg.listen_host == "127.0.0.1":
            try:
                v6_transport, _ = await loop.create_datagram_endpoint(
                    lambda: _LocalDnsUdpProtocol(self),
                    local_addr=("::1", self.bound_port),
                )
                self._udp_v6_transport = v6_transport
            except OSError as exc:
                LOG.debug("DNS UDP IPv6 (::1) indisponível na porta %s: %s", self.bound_port, exc)

        try:
            self._tcp_server = await asyncio.start_server(
                self._handle_tcp_client,
                self.cfg.listen_host,
                self.bound_port,
            )
        except OSError as exc:
            LOG.debug("DNS TCP opcional indisponível na porta %s: %s", self.bound_port, exc)

        self.running = True
        LOG.info("Servidor DNS local Qproxy ativo em %s:%s", self.cfg.listen_host, self.bound_port)

    async def stop(self) -> None:
        self.running = False
        if self._udp_transport is not None:
            self._udp_transport.close()
            self._udp_transport = None
        if self._udp_v6_transport is not None:
            self._udp_v6_transport.close()
            self._udp_v6_transport = None
        if self._tcp_server is not None:
            self._tcp_server.close()
            try:
                await self._tcp_server.wait_closed()
            except Exception:
                pass
            self._tcp_server = None
