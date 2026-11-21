"""Motor de filtragem de pacotes do Windows (WinDivert / WFP).

Intercepta apenas os pacotes de controle necessários no kernel do Windows
(DNS, TLS ClientHello, QUIC Initial e cabeçalhos HTTP) antes que cheguem às
aplicações ou saiam para a rede. Todo o tráfego de dados permitido (vídeos,
downloads, jogos) permanece 100% no kernel do Windows na velocidade nativa.
"""
from __future__ import annotations

from dataclasses import dataclass
import logging
from pathlib import Path
from threading import Event, Thread
from typing import Callable

from .blocklist import RuleManager
from .config import PacketFilterConfig
from .dns_cache import DnsPacketCache
from .packet_parser import (
    IPPROTO_TCP,
    IPPROTO_UDP,
    ParsedPacket,
    build_dns_blocked_from_response,
    build_dns_blocked_payload,
    build_http_blocked_packet,
    build_tcp_rst_packet,
    build_udp_packet_same_direction,
    build_udp_reply_packet,
    extract_http_request,
    extract_tls_sni,
    parse_dns_query,
    parse_dns_response,
    parse_ip_packet,
    rewrite_dns_cached_payload,
)
from .quic_sni import extract_quic_initial_sni
from .stats import StatsStore
from .windivert import WinDivertHandle, clone_address_for_direction

LOG = logging.getLogger("qproxy")

DOH_CANARY_DOMAIN = "use-application-dns.net"


@dataclass(frozen=True, slots=True)
class PacketInjection:
    data: bytes
    outbound: bool
    recalc_checksums: bool = True
    is_ipv6: bool = False


@dataclass(frozen=True, slots=True)
class PacketDecision:
    pass_original: bool
    injections: tuple[PacketInjection, ...] = ()
    protocol: str | None = None
    host: str | None = None
    blocked: bool = False
    cache_hit: bool = False
    rule: str | None = None
    category: str | None = None


def build_windivert_filter(cfg: PacketFilterConfig) -> str:
    """Constrói expressão de filtro WinDivert 2.2 altamente seletiva.

    Apenas pacotes de controle (DNS, ClientHello TLS, Initial QUIC e cabeçalho
    HTTP) entram no espaço de usuário; dados em massa ficam no kernel.
    """
    clauses: list[str] = []
    if cfg.filter_dns:
        clauses.append("(outbound and udp.DstPort == 53 and udp.PayloadLength >= 17)")
        if cfg.filter_cname_cloaking or cfg.dns_cache_enabled:
            clauses.append("(inbound and udp.SrcPort == 53 and udp.PayloadLength >= 12)")
    if cfg.filter_tls_sni:
        clauses.append(
            "(outbound and (tcp.DstPort == 443 or tcp.DstPort == 8443) "
            "and tcp.PayloadLength >= 47 and tcp.Payload[0] == 0x16 "
            "and tcp.Payload[1] == 0x03 and tcp.Payload[5] == 0x01)"
        )
    if cfg.filter_http:
        clauses.append(
            "(outbound and (tcp.DstPort == 80 or tcp.DstPort == 8080) "
            "and tcp.PayloadLength >= 16 "
            "and (tcp.Payload[0] == 0x47 or tcp.Payload[0] == 0x50 "
            "or tcp.Payload[0] == 0x48 or tcp.Payload[0] == 0x44 or tcp.Payload[0] == 0x4F))"
        )
    if cfg.filter_quic_sni:
        clauses.append(
            "(outbound and udp.DstPort == 443 and udp.PayloadLength >= 1200 "
            "and udp.Payload[0] >= 0xC0 and udp.Payload[0] <= 0xDF)"
        )
    if cfg.block_dot:
        clauses.append(
            "(outbound and tcp.DstPort == 853 and tcp.PayloadLength >= 47 "
            "and tcp.Payload[0] == 0x16)"
        )
    if not clauses:
        return "false"
    return "!loopback and !impostor and (" + " or ".join(clauses) + ")"


class PacketProcessor:
    """Núcleo independente de SO para inspeção e bloqueio de pacotes IP."""

    def __init__(
        self,
        rules: RuleManager,
        stats: StatsStore,
        cfg: PacketFilterConfig,
        dns_cache: DnsPacketCache | None = None,
        log_allowed: bool = False,
    ) -> None:
        self.rules = rules
        self.stats = stats
        self.cfg = cfg
        self.dns_cache = dns_cache
        self.log_allowed = log_allowed

    def process_packet(self, raw: bytes, outbound: bool) -> PacketDecision:
        self.stats.record_packet_inspected()
        if self.rules.is_paused():
            self.stats.record_packet_passed()
            return PacketDecision(pass_original=True)

        pkt = parse_ip_packet(raw)
        if pkt is None:
            self.stats.record_packet_passed()
            return PacketDecision(pass_original=True)

        if pkt.protocol == IPPROTO_UDP:
            if outbound and pkt.dst_port == 53 and self.cfg.filter_dns:
                return self._handle_dns_query(pkt)
            if not outbound and pkt.src_port == 53 and self.cfg.filter_dns:
                return self._handle_dns_response(pkt)
            if outbound and pkt.dst_port == 443 and self.cfg.filter_quic_sni:
                return self._handle_quic_initial(pkt)
        elif pkt.protocol == IPPROTO_TCP:
            if outbound and pkt.dst_port == 853 and self.cfg.block_dot:
                return self._handle_dot_block(pkt)
            if outbound and pkt.dst_port in (443, 8443) and self.cfg.filter_tls_sni:
                return self._handle_tls_client_hello(pkt)
            if outbound and pkt.dst_port in (80, 8080) and self.cfg.filter_http:
                return self._handle_http_request(pkt)

        self.stats.record_packet_passed()
        return PacketDecision(pass_original=True)

    def _handle_dns_query(self, pkt: ParsedPacket) -> PacketDecision:
        query = parse_dns_query(pkt.payload)
        if query is None:
            self.stats.record_packet_passed()
            return PacketDecision(pass_original=True)

        # Sinal oficial RFC (Mozilla/Firefox) para usar o DNS local filtrado/cacheado
        if self.cfg.signal_local_dns_filter and query.qname == DOH_CANARY_DOMAIN:
            reply_payload = build_dns_blocked_payload(pkt.payload, mode="nxdomain", ttl=60)
            if reply_payload:
                reply_pkt = build_udp_reply_packet(pkt, reply_payload)
                self.stats.record_packet_blocked()
                return PacketDecision(
                    pass_original=False,
                    injections=(PacketInjection(reply_pkt, outbound=False, is_ipv6=pkt.is_ipv6),),
                    protocol="dns",
                    host=query.qname,
                    blocked=True,
                    rule="doh-canary",
                    category="dns",
                )

        decision = self.rules.evaluate(query.qname)
        if decision.blocked:
            reply_payload = build_dns_blocked_payload(
                pkt.payload, mode=self.cfg.dns_block_mode, ttl=60
            )
            injections: tuple[PacketInjection, ...] = ()
            if reply_payload:
                reply_pkt = build_udp_reply_packet(pkt, reply_payload)
                injections = (PacketInjection(reply_pkt, outbound=False, is_ipv6=pkt.is_ipv6),)
            self.stats.record(query.qname, "blocked", "dns", decision.category, decision.rule)
            self.stats.record_packet_blocked()
            LOG.info("BLOCK DNS %s [%s]", query.qname, decision.category or "ad")
            return PacketDecision(
                pass_original=False,
                injections=injections,
                protocol="dns",
                host=query.qname,
                blocked=True,
                rule=decision.rule,
                category=decision.category,
            )

        # Aceleração: resposta instantânea (<0.5ms) via cache DNS em RAM
        if self.cfg.dns_cache_enabled and self.dns_cache is not None:
            cached = self.dns_cache.get(query.qname, query.qtype)
            if cached is not None:
                cached_payload, remaining_ttl = cached
                rewritten = rewrite_dns_cached_payload(cached_payload, query.txid, remaining_ttl)
                reply_pkt = build_udp_reply_packet(pkt, rewritten)
                self.stats.record_dns_cache(hit=True)
                self.stats.record_packet_passed()
                return PacketDecision(
                    pass_original=False,
                    injections=(PacketInjection(reply_pkt, outbound=False, is_ipv6=pkt.is_ipv6),),
                    protocol="dns",
                    host=query.qname,
                    blocked=False,
                    cache_hit=True,
                )
            self.stats.record_dns_cache(hit=False)

        self.stats.record(query.qname, "allowed", "dns", rule=decision.rule)
        if self.log_allowed:
            LOG.info("ALLOW DNS %s", query.qname)
        self.stats.record_packet_passed()
        return PacketDecision(pass_original=True, protocol="dns", host=query.qname)

    def _handle_dns_response(self, pkt: ParsedPacket) -> PacketDecision:
        resp = parse_dns_response(pkt.payload)
        if resp is None:
            self.stats.record_packet_passed()
            return PacketDecision(pass_original=True)

        # Proteção contra CNAME cloaking (subdomínio first-party apontando para tracker)
        if (
            self.cfg.filter_cname_cloaking
            and resp.cnames
            and resp.qname
            and not self.rules.is_whitelisted(resp.qname)
        ):
            for cname in resp.cnames:
                cname_decision = self.rules.evaluate(cname)
                if cname_decision.blocked:
                    blocked_payload = build_dns_blocked_from_response(
                        pkt.payload, mode=self.cfg.dns_block_mode, ttl=60
                    )
                    if blocked_payload:
                        replaced = build_udp_packet_same_direction(pkt, blocked_payload)
                        rule_name = f"cname:{cname_decision.rule or cname}"
                        self.stats.record(
                            resp.qname,
                            "blocked",
                            "cname",
                            cname_decision.category or "tracker",
                            rule_name,
                        )
                        self.stats.record_packet_blocked()
                        LOG.info("BLOCK CNAME %s -> %s", resp.qname, cname)
                        return PacketDecision(
                            pass_original=False,
                            injections=(
                                PacketInjection(replaced, outbound=False, is_ipv6=pkt.is_ipv6),
                            ),
                            protocol="cname",
                            host=resp.qname,
                            blocked=True,
                            rule=rule_name,
                            category=cname_decision.category or "tracker",
                        )

        if (
            self.cfg.dns_cache_enabled
            and self.dns_cache is not None
            and resp.rcode == 0
            and resp.answer_count > 0
            and resp.qname
            and not self.rules.is_blocked(resp.qname)
        ):
            self.dns_cache.put(resp.qname, resp.qtype, pkt.payload, resp.min_ttl)

        self.stats.record_packet_passed()
        return PacketDecision(pass_original=True, protocol="dns", host=resp.qname)

    def _handle_tls_client_hello(self, pkt: ParsedPacket) -> PacketDecision:
        sni = extract_tls_sni(pkt.payload)
        if not sni:
            self.stats.record_packet_passed()
            return PacketDecision(pass_original=True)

        decision = self.rules.evaluate(sni)
        if decision.blocked:
            rst_client = build_tcp_rst_packet(pkt, to_client=True)
            rst_server = build_tcp_rst_packet(pkt, to_client=False)
            self.stats.record(sni, "blocked", "tls", decision.category, decision.rule)
            self.stats.record_packet_blocked()
            LOG.info("BLOCK TLS-SNI %s [%s]", sni, decision.category or "ad")
            return PacketDecision(
                pass_original=False,
                injections=(
                    PacketInjection(rst_client, outbound=False, is_ipv6=pkt.is_ipv6),
                    PacketInjection(rst_server, outbound=True, is_ipv6=pkt.is_ipv6),
                ),
                protocol="tls",
                host=sni,
                blocked=True,
                rule=decision.rule,
                category=decision.category,
            )

        self.stats.record(sni, "allowed", "tls", rule=decision.rule)
        if self.log_allowed:
            LOG.info("ALLOW TLS-SNI %s", sni)
        self.stats.record_packet_passed()
        return PacketDecision(pass_original=True, protocol="tls", host=sni)

    def _handle_quic_initial(self, pkt: ParsedPacket) -> PacketDecision:
        sni = extract_quic_initial_sni(pkt.payload)
        if not sni:
            self.stats.record_packet_passed()
            return PacketDecision(pass_original=True)

        decision = self.rules.evaluate(sni)
        if decision.blocked:
            self.stats.record(sni, "blocked", "quic", decision.category, decision.rule)
            self.stats.record_packet_blocked()
            LOG.info("BLOCK QUIC-SNI %s [%s]", sni, decision.category or "ad")
            return PacketDecision(
                pass_original=False,
                injections=(),
                protocol="quic",
                host=sni,
                blocked=True,
                rule=decision.rule,
                category=decision.category,
            )

        self.stats.record(sni, "allowed", "quic", rule=decision.rule)
        if self.log_allowed:
            LOG.info("ALLOW QUIC-SNI %s", sni)
        self.stats.record_packet_passed()
        return PacketDecision(pass_original=True, protocol="quic", host=sni)

    def _handle_http_request(self, pkt: ParsedPacket) -> PacketDecision:
        req = extract_http_request(pkt.payload)
        if req is None:
            self.stats.record_packet_passed()
            return PacketDecision(pass_original=True)

        decision = self.rules.evaluate_http(req.host, req.path)
        if decision.blocked:
            http_reply = build_http_blocked_packet(pkt)
            rst_server = build_tcp_rst_packet(pkt, to_client=False)
            self.stats.record(req.host, "blocked", "http", decision.category, decision.rule)
            self.stats.record_packet_blocked()
            LOG.info("BLOCK HTTP-PKT %s%s [%s]", req.host, req.path[:64], decision.category or "ad")
            return PacketDecision(
                pass_original=False,
                injections=(
                    PacketInjection(http_reply, outbound=False, is_ipv6=pkt.is_ipv6),
                    PacketInjection(rst_server, outbound=True, is_ipv6=pkt.is_ipv6),
                ),
                protocol="http",
                host=req.host,
                blocked=True,
                rule=decision.rule,
                category=decision.category,
            )

        self.stats.record(req.host, "allowed", "http", rule=decision.rule)
        if self.log_allowed:
            LOG.info("ALLOW HTTP-PKT %s%s", req.host, req.path[:64])
        self.stats.record_packet_passed()
        return PacketDecision(pass_original=True, protocol="http", host=req.host)

    def _handle_dot_block(self, pkt: ParsedPacket) -> PacketDecision:
        sni = extract_tls_sni(pkt.payload) or pkt.dst_ip_str
        rst_client = build_tcp_rst_packet(pkt, to_client=True)
        rst_server = build_tcp_rst_packet(pkt, to_client=False)
        self.stats.record(sni, "blocked", "dot", "dns", "dot-port-853")
        self.stats.record_packet_blocked()
        LOG.info("BLOCK DoT %s:853", sni)
        return PacketDecision(
            pass_original=False,
            injections=(
                PacketInjection(rst_client, outbound=False, is_ipv6=pkt.is_ipv6),
                PacketInjection(rst_server, outbound=True, is_ipv6=pkt.is_ipv6),
            ),
            protocol="dot",
            host=sni,
            blocked=True,
            rule="dot-port-853",
            category="dns",
        )


class WindowsPacketFilter:
    """Executor em thread dedicada conectado ao driver WinDivert no Windows."""

    def __init__(
        self,
        dll_path: Path,
        processor: PacketProcessor,
        cfg: PacketFilterConfig,
        handle_factory: Callable[[Path, str], WinDivertHandle] | None = None,
    ) -> None:
        self.dll_path = Path(dll_path)
        self.processor = processor
        self.cfg = cfg
        self._handle_factory = handle_factory or (lambda p, f: WinDivertHandle(p, f))
        self.filter_expr = build_windivert_filter(cfg)
        self._handle: WinDivertHandle | None = None
        self._thread: Thread | None = None
        self._stop_event = Event()
        self.running = False
        self.error: str | None = None

    def start(self) -> None:
        handle = self._handle_factory(self.dll_path, self.filter_expr)
        try:
            handle.configure_queues()
        except Exception:
            pass
        self._handle = handle
        self._stop_event.clear()
        self.running = True
        self.error = None
        self._thread = Thread(target=self._loop, name="qproxy-packet-filter", daemon=True)
        self._thread.start()
        LOG.info("Filtro de pacotes Windows (WinDivert) ATIVO: %s", ", ".join(self.active_layers()))

    def active_layers(self) -> list[str]:
        layers: list[str] = []
        if self.cfg.filter_dns:
            layers.append("DNS (UDP 53)")
        if self.cfg.filter_cname_cloaking and self.cfg.filter_dns:
            layers.append("CNAME Cloaking")
        if self.cfg.dns_cache_enabled and self.cfg.filter_dns:
            layers.append("Cache DNS <1ms")
        if self.cfg.filter_tls_sni:
            layers.append("TLS SNI (TCP 443)")
        if self.cfg.filter_quic_sni:
            layers.append("QUIC/HTTP3 SNI (UDP 443)")
        if self.cfg.filter_http:
            layers.append("HTTP Host/Path (TCP 80)")
        if self.cfg.block_dot:
            layers.append("DoT (TCP 853)")
        return layers

    def _loop(self) -> None:
        handle = self._handle
        if handle is None:
            return
        try:
            while not self._stop_event.is_set():
                item = handle.recv()
                if item is None:
                    break
                raw, addr = item
                try:
                    decision = self.processor.process_packet(raw, bool(addr.Outbound))
                except Exception as exc:
                    # Fail-open seguro: jamais travar a rede em caso de pacote exótico
                    LOG.debug("Erro ao analisar pacote (fail-open): %r", exc)
                    handle.send(raw, addr, recalc_checksums=False)
                    continue

                if decision.pass_original:
                    handle.send(raw, addr, recalc_checksums=False)

                for inj in decision.injections:
                    inj_addr = clone_address_for_direction(
                        addr, outbound=inj.outbound, is_ipv6=inj.is_ipv6
                    )
                    handle.send(inj.data, inj_addr, recalc_checksums=inj.recalc_checksums)
        except Exception as exc:
            if not self._stop_event.is_set():
                self.error = str(exc)
                LOG.error("Motor WinDivert encerrado com erro: %s", exc)
        finally:
            self.running = False

    def stop(self) -> None:
        self._stop_event.set()
        if self._handle is not None:
            try:
                self._handle.shutdown()
            except Exception:
                pass
        if self._thread is not None:
            self._thread.join(timeout=3)
        if self._handle is not None:
            try:
                self._handle.close()
            except Exception:
                pass
            self._handle = None
        self.running = False
