import ctypes
import io
import tempfile
import unittest
from pathlib import Path
import zipfile

from qproxy.blocklist import RuleManager
from qproxy.config import PacketFilterConfig
from qproxy.dns_cache import DnsPacketCache
from qproxy.packet_filter import (
    DOH_CANARY_DOMAIN,
    PacketProcessor,
    WindowsPacketFilter,
    build_windivert_filter,
)
from qproxy.packet_parser import (
    DNS_TYPE_A,
    TCP_ACK,
    TCP_FIN,
    TCP_PSH,
    TCP_RST,
    parse_dns_response,
    parse_ip_packet,
)
from qproxy.quic_sni import QUIC_V1, build_quic_initial_packet
from qproxy.stats import StatsStore
from qproxy.windivert import WinDivertAddress, clone_address_for_direction
from qproxy.windivert_setup import install_windivert_from_zip_bytes
from tests.test_packet_parser import (
    make_dns_a_response,
    make_dns_cname_response,
    make_dns_query,
    make_ipv4_tcp,
    make_ipv4_udp,
    make_tls_client_hello,
)
from tests.test_quic_sni import _make_tls_handshake_client_hello


class _FakeWinDivertHandle:
    def __init__(self, packets: list[tuple[bytes, bool]]):
        self._queue = list(packets)
        self.sent: list[tuple[bytes, bool, bool]] = []
        self.closed = False

    def configure_queues(self):
        pass

    def recv(self):
        if not self._queue:
            return None
        raw, outbound = self._queue.pop(0)
        addr = WinDivertAddress()
        addr.Outbound = 1 if outbound else 0
        addr.Network.IfIdx = 7
        addr.Network.SubIfIdx = 2
        return raw, addr

    def send(self, packet: bytes, addr: WinDivertAddress, recalc_checksums: bool = False):
        self.sent.append((packet, bool(addr.Outbound), recalc_checksums))
        return True

    def shutdown(self):
        self._queue.clear()

    def close(self):
        self.closed = True


class PacketFilterTests(unittest.TestCase):
    def _make_runtime(self, directory: str):
        root = Path(directory)
        bl = root / "blocklist.txt"
        bl.write_text("doubleclick.net\ncriteo.com\nads.tiktok.com\n", encoding="utf-8")
        wl = root / "whitelist.txt"
        wl.write_text("", encoding="utf-8")
        rules = RuleManager([(bl, "ad")], [wl], ["youtube.com", "googlevideo.com"], root / "manual.txt")
        stats = StatsStore(root / "stats.json")
        cache = DnsPacketCache()
        cfg = PacketFilterConfig()
        processor = PacketProcessor(rules, stats, cfg, dns_cache=cache)
        return rules, stats, cache, cfg, processor

    def test_windivert_filter_syntax_and_address_abi(self):
        expr = build_windivert_filter(PacketFilterConfig())
        self.assertIn("!loopback and !impostor", expr)
        self.assertIn("udp.DstPort == 53", expr)
        self.assertIn("tcp.Payload[0] == 0x16", expr)
        self.assertIn("udp.Payload[0] >= 0xC0 and udp.Payload[0] <= 0xDF", expr)
        # WinDivert 2.2 não suporta operador bitwise '&'
        self.assertNotIn("&", expr)
        self.assertEqual(ctypes.sizeof(WinDivertAddress), 80)

        src = WinDivertAddress()
        src.Outbound = 1
        src.Network.IfIdx = 12
        src.Network.SubIfIdx = 3
        cloned = clone_address_for_direction(src, outbound=False, is_ipv6=False)
        self.assertEqual(cloned.Outbound, 0)
        self.assertEqual(cloned.Network.IfIdx, 12)
        self.assertEqual(cloned.Network.SubIfIdx, 3)

    def test_dns_block_cache_and_doh_canary(self):
        with tempfile.TemporaryDirectory() as d:
            rules, stats, cache, _, processor = self._make_runtime(d)

            # 1. Domínio de anúncio bloqueado instantaneamente (0.0.0.0 inbound)
            q_ad = make_ipv4_udp("192.168.1.5", "8.8.8.8", 50000, 53, make_dns_query("ads.doubleclick.net", txid=0x1001))
            dec = processor.process_packet(q_ad, outbound=True)
            self.assertFalse(dec.pass_original)
            self.assertTrue(dec.blocked)
            self.assertEqual(dec.protocol, "dns")
            self.assertEqual(len(dec.injections), 1)
            self.assertFalse(dec.injections[0].outbound)
            reply = parse_ip_packet(dec.injections[0].data)
            self.assertTrue(reply.payload.endswith(b"\x00\x00\x00\x00"))

            # 2. Canário DoH -> NXDOMAIN
            q_canary = make_ipv4_udp("192.168.1.5", "8.8.8.8", 50001, 53, make_dns_query(DOH_CANARY_DOMAIN, txid=0x1002))
            dec_c = processor.process_packet(q_canary, outbound=True)
            self.assertFalse(dec_c.pass_original)
            resp_c = parse_dns_response(parse_ip_packet(dec_c.injections[0].data).payload)
            self.assertEqual(resp_c.rcode, 3)

            # 3. Domínio permitido -> miss -> resposta popula cache -> segunda consulta responde do cache
            q_ok1 = make_ipv4_udp("192.168.1.5", "8.8.8.8", 50002, 53, make_dns_query("www.example.org", txid=0x2001))
            dec1 = processor.process_packet(q_ok1, outbound=True)
            self.assertTrue(dec1.pass_original)
            self.assertFalse(dec1.cache_hit)

            resp_in = make_ipv4_udp("8.8.8.8", "192.168.1.5", 53, 50002, make_dns_a_response("www.example.org", ttl=200, txid=0x2001))
            dec_in = processor.process_packet(resp_in, outbound=False)
            self.assertTrue(dec_in.pass_original)

            q_ok2 = make_ipv4_udp("192.168.1.5", "8.8.8.8", 50003, 53, make_dns_query("www.example.org", txid=0x9876))
            dec2 = processor.process_packet(q_ok2, outbound=True)
            self.assertFalse(dec2.pass_original)
            self.assertTrue(dec2.cache_hit)
            cached_resp = parse_dns_response(parse_ip_packet(dec2.injections[0].data).payload)
            self.assertEqual(cached_resp.txid, 0x9876)
            self.assertEqual(stats.snapshot()["dns_cache_hits"], 1)

    def test_cname_cloaking_blocked_unless_whitelisted(self):
        with tempfile.TemporaryDirectory() as d:
            rules, _, _, _, processor = self._make_runtime(d)
            cloaked = make_ipv4_udp(
                "8.8.8.8", "192.168.1.5", 53, 51000,
                make_dns_cname_response("metrics.loja.com.br", "track.criteo.com"),
            )
            dec = processor.process_packet(cloaked, outbound=False)
            self.assertFalse(dec.pass_original)
            self.assertTrue(dec.blocked)
            self.assertEqual(dec.protocol, "cname")
            replaced = parse_ip_packet(dec.injections[0].data)
            self.assertTrue(replaced.payload.endswith(b"\x00\x00\x00\x00"))

            # Se o domínio first-party for liberado pelo usuário, CNAME não é bloqueado
            rules.add_to_whitelist("metrics.loja.com.br")
            dec_wl = processor.process_packet(cloaked, outbound=False)
            self.assertTrue(dec_wl.pass_original)
            self.assertFalse(dec_wl.blocked)

    def test_tls_sni_quic_sni_and_http_path_blocking(self):
        with tempfile.TemporaryDirectory() as d:
            rules, stats, _, _, processor = self._make_runtime(d)

            # TLS SNI bloqueado -> drop + RST cliente e servidor
            tls_ad = make_ipv4_tcp("192.168.1.5", "142.250.1.1", 52000, 443, make_tls_client_hello("pub.doubleclick.net"))
            dec_tls = processor.process_packet(tls_ad, outbound=True)
            self.assertFalse(dec_tls.pass_original)
            self.assertTrue(dec_tls.blocked)
            self.assertEqual(dec_tls.protocol, "tls")
            self.assertEqual(len(dec_tls.injections), 2)
            self.assertEqual(parse_ip_packet(dec_tls.injections[0].data).tcp_flags, TCP_RST | TCP_ACK)

            # TLS SNI permitido (YouTube) -> passa intacto
            tls_yt = make_ipv4_tcp("192.168.1.5", "142.250.1.2", 52001, 443, make_tls_client_hello("www.youtube.com"))
            dec_yt = processor.process_packet(tls_yt, outbound=True)
            self.assertTrue(dec_yt.pass_original)
            self.assertFalse(dec_yt.blocked)

            # QUIC Initial (HTTP/3) bloqueado
            quic_ad_payload = build_quic_initial_packet(_make_tls_handshake_client_hello("ads.tiktok.com"), version=QUIC_V1)
            quic_ad = make_ipv4_udp("192.168.1.5", "23.1.2.3", 53000, 443, quic_ad_payload)
            dec_q = processor.process_packet(quic_ad, outbound=True)
            self.assertFalse(dec_q.pass_original)
            self.assertTrue(dec_q.blocked)
            self.assertEqual(dec_q.protocol, "quic")

            # HTTP caminho publicitário em domínio não bloqueado -> HTTP 204 + FIN
            http_req = b"GET /pagead/js/adsbygoogle.js HTTP/1.1\r\nHost: www.portal.test\r\n\r\n"
            http_pkt = make_ipv4_tcp("192.168.1.5", "93.184.216.34", 54000, 80, http_req)
            dec_http = processor.process_packet(http_pkt, outbound=True)
            self.assertFalse(dec_http.pass_original)
            self.assertTrue(dec_http.blocked)
            self.assertEqual(dec_http.protocol, "http")
            in_pkt = parse_ip_packet(dec_http.injections[0].data)
            self.assertEqual(in_pkt.tcp_flags, TCP_PSH | TCP_ACK | TCP_FIN)
            self.assertIn(b"204 No Content", in_pkt.payload)

            # Pausa interrompe imediatamente o bloqueio em pacotes
            rules.pause_for(60)
            self.assertTrue(processor.process_packet(tls_ad, outbound=True).pass_original)
            rules.resume()
            self.assertFalse(processor.process_packet(tls_ad, outbound=True).pass_original)

            snap = stats.snapshot()
            self.assertGreaterEqual(snap["packets_blocked"], 4)
            self.assertGreaterEqual(snap["blocked_by_protocol"]["tls"], 2)
            self.assertGreaterEqual(snap["blocked_by_protocol"]["quic"], 1)

    def test_windows_packet_filter_worker_loop_and_installer(self):
        with tempfile.TemporaryDirectory() as d:
            _, _, _, cfg, processor = self._make_runtime(d)
            pkt_ad = make_ipv4_udp("192.168.1.5", "8.8.8.8", 55555, 53, make_dns_query("ads.doubleclick.net"))
            pkt_ok = make_ipv4_tcp("192.168.1.5", "142.250.1.2", 55556, 443, make_tls_client_hello("www.youtube.com"))
            fake = _FakeWinDivertHandle([(pkt_ad, True), (pkt_ok, True)])
            wf = WindowsPacketFilter(Path(d) / "WinDivert.dll", processor, cfg, handle_factory=lambda *_: fake)
            wf.start()
            wf._thread.join(timeout=2)
            wf.stop()
            self.assertTrue(fake.closed)
            # 1 resposta DNS forjada inbound (outbound=False) + 1 pacote YouTube re-injetado outbound=True
            self.assertEqual(len(fake.sent), 2)
            self.assertFalse(fake.sent[0][1])
            self.assertTrue(fake.sent[1][1])

            # Validação de integridade SHA-256 do instalador WinDivert
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr("WinDivert-2.2.2-A/x64/WinDivert.dll", b"dll-bytes")
                zf.writestr("WinDivert-2.2.2-A/x64/WinDivert64.sys", b"sys-bytes")
                zf.writestr("WinDivert-2.2.2-A/x86/WinDivert.dll", b"dll-bytes")
                zf.writestr("WinDivert-2.2.2-A/x86/WinDivert32.sys", b"sys-bytes")
            with self.assertRaises(ValueError):
                install_windivert_from_zip_bytes(buf.getvalue(), Path(d) / "wd_bad", verify_sha256=True)
            dll = install_windivert_from_zip_bytes(buf.getvalue(), Path(d) / "wd_ok", verify_sha256=False)
            self.assertTrue(dll.is_file())


if __name__ == "__main__":
    unittest.main()
