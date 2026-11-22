import asyncio
import contextlib
import io
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from qproxy.blocklist import RuleManager
from qproxy.browser_setup import (
    BrowserInfo,
    BrowserSetupResult,
    print_browser_setup,
    setup_browser_companion,
)
from qproxy.config import BrowserCompanionConfig, Config, PacketFilterConfig, RemoteListSource
from qproxy.dashboard import DashboardServer
from qproxy.dns_cache import DnsPacketCache, HostAddressCache
from qproxy.dns_server import LocalDnsServer
from qproxy.packet_filter import PacketProcessor, WindowsPacketFilter, build_windivert_filter
from qproxy.packet_parser import (
    DNS_TYPE_SVCB,
    IPPROTO_TCP,
    IPPROTO_UDP,
    TCP_RST,
    build_dns_blocked_from_response,
    build_dns_blocked_payload,
    build_tcp_rst_packet,
    build_udp_reply_packet,
    extract_http_request,
    parse_dns_response,
    parse_ip_packet,
)
from qproxy.proxy import ProxyServer, _parse_host_port, _rewrite_http_request
from qproxy.quic_sni import (
    QUIC_V1,
    _WinBCryptBackend,
    _extract_crypto_stream,
    _read_varint,
    build_quic_initial_packet,
    extract_quic_initial_sni,
)
from qproxy.stats import StatsStore
from qproxy.updater import BlocklistUpdater
from tests.test_cli_and_launcher import _FakeWinReg
from tests.test_packet_parser import (
    make_dns_a_response,
    make_dns_query,
    make_ipv4_tcp,
    make_ipv4_udp,
    make_ipv6_tcp,
    make_tls_client_hello,
)
from tests.test_quic_sni import _make_tls_handshake_client_hello


class PacketParserAndQuicEdgeCaseTests(unittest.TestCase):
    def test_ipv6_extension_headers_and_fragment_handling(self):
        import socket

        # IPv6 + Hop-by-Hop (0, 8 bytes) -> TCP
        tcp_hdr = struct.pack("!HHIIHHHH", 50000, 443, 1, 2, (5 << 12) | 0x18, 65535, 0, 0)
        hbh = struct.pack("!BB6x", IPPROTO_TCP, 0)
        l4 = hbh + tcp_hdr + b"payload"
        pkt = struct.pack(
            "!IHBB16s16s",
            0x60000000, len(l4), 0, 64,
            socket.inet_pton(socket.AF_INET6, "2001:db8::1"),
            socket.inet_pton(socket.AF_INET6, "2001:db8::2"),
        ) + l4
        parsed = parse_ip_packet(pkt)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.protocol, IPPROTO_TCP)
        self.assertEqual(parsed.payload, b"payload")

        # IPv6 Fragment header com offset != 0 é ignorado
        frag = struct.pack("!BBHI", IPPROTO_UDP, 0, 0x0008, 1234)
        pkt_frag = struct.pack(
            "!IHBB16s16s",
            0x60000000, len(frag) + 8, 44, 64,
            socket.inet_pton(socket.AF_INET6, "2001:db8::1"),
            socket.inet_pton(socket.AF_INET6, "2001:db8::2"),
        ) + frag + (b"\x00" * 8)
        self.assertIsNone(parse_ip_packet(pkt_frag))

        # Pacote curto/versão desconhecida -> None
        self.assertIsNone(parse_ip_packet(b"\x00" * 10))
        self.assertIsNone(parse_ip_packet(b"\x35" + b"\x00" * 24))

    def test_svcb_txt_outbound_rst_and_ipv6_http_host(self):
        q_svcb = make_dns_query("ads.test", DNS_TYPE_SVCB)
        r_svcb = parse_dns_response(build_dns_blocked_payload(q_svcb, mode="zero_ip"))
        self.assertEqual(r_svcb.rcode, 0)
        self.assertEqual(r_svcb.answer_count, 0)

        q_txt = make_dns_query("ads.test", 16)
        r_txt = parse_dns_response(build_dns_blocked_payload(q_txt, mode="zero_ip"))
        self.assertEqual(r_txt.rcode, 3)

        orig_resp = make_dns_a_response("ads.test")
        blocked_from_resp = build_dns_blocked_from_response(orig_resp)
        self.assertTrue(blocked_from_resp.endswith(b"\x00\x00\x00\x00"))
        self.assertIsNone(build_dns_blocked_from_response(b"short"))

        tcp_pkt = parse_ip_packet(make_ipv4_tcp("192.168.1.2", "1.2.3.4", 5555, 443, b"x", seq=99, ack=77))
        rst_server = parse_ip_packet(build_tcp_rst_packet(tcp_pkt, to_client=False))
        self.assertEqual(rst_server.tcp_flags, TCP_RST)
        self.assertEqual(rst_server.tcp_seq, 99)

        http_v6 = extract_http_request(b"GET /ads/ad.js HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n")
        self.assertIsNotNone(http_v6)
        self.assertEqual(http_v6.host, "::1")
        self.assertIsNone(extract_http_request(b"GET /nohost HTTP/1.1\r\n\r\n"))

    def test_quic_varints_crypto_stream_and_mocked_win_bcrypt(self):
        # 1, 2, 4, 8 byte varints
        self.assertEqual(_read_varint(b"\x25", 0), (0x25, 1))
        self.assertEqual(_read_varint(b"\x7b\xbd", 0), (15293, 2))
        self.assertEqual(_read_varint(b"\x9d\x7f\x3e\x7d", 0), (494878333, 4))
        self.assertEqual(_read_varint(b"\xc2\x19\x7c\x5e\xff\x14\xe8\x8c", 0), (151288809941952652, 8))

        # Reconstrução de CRYPTO frames fora de ordem e com sobreposição
        stream = _extract_crypto_stream(
            b"\x06\x05\x05world" + b"\x06\x00\x05hello" + b"\x00"
        )
        self.assertEqual(stream, b"helloworld")

        # Versão ou tipo QUIC inválido -> None
        valid_pkt = bytearray(build_quic_initial_packet(_make_tls_handshake_client_hello("ads.test"), version=QUIC_V1))
        valid_pkt[-1] ^= 0xFF  # Corrompe tag AES-GCM
        self.assertIsNone(extract_quic_initial_sni(bytes(valid_pkt)))
        self.assertIsNone(extract_quic_initial_sni(b"\xc0\xde\xad\xbe\xef" + b"\x00" * 100))

        # Simula WinDLL("bcrypt") em qualquer SO
        fake_dll = MagicMock()
        fake_dll.BCryptOpenAlgorithmProvider.return_value = 0
        fake_dll.BCryptSetProperty.return_value = 0
        fake_dll.BCryptGenerateSymmetricKey.return_value = 0
        fake_dll.BCryptDestroyKey.return_value = 0

        def fake_encrypt(_hkey, in_buf, _in_len, _p4, _p5, _p6, out_buf, _out_len, out_len_ptr, _flags):
            expected = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
            import ctypes
            ctypes.memmove(out_buf, expected, 16)
            out_len_ptr._obj.value = 16
            return 0

        def fake_decrypt(_hkey, _in_buf, _in_len, _p4, _p5, _p6, out_buf, _out_len, out_len_ptr, _flags):
            import ctypes
            ctypes.memmove(out_buf, b"xyz", 3)
            out_len_ptr._obj.value = 3
            return 0

        fake_dll.BCryptEncrypt.side_effect = fake_encrypt
        fake_dll.BCryptDecrypt.side_effect = fake_decrypt
        with patch("qproxy.quic_sni.ctypes.WinDLL", return_value=fake_dll, create=True):
            backend = _WinBCryptBackend()
            self.assertEqual(
                backend.ecb_encrypt(bytes(16), bytes(16)),
                bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"),
            )
            self.assertEqual(backend.gcm_decrypt(bytes(16), bytes(12), b"abc", bytes(16), b"aad"), b"xyz")


class PacketFilterAndDnsEdgeCaseTests(unittest.TestCase):
    def test_filter_builder_toggles_and_dot_ipv6_fail_open(self):
        cfg_none = PacketFilterConfig(
            filter_dns=False, filter_tls_sni=False, filter_http=False, filter_quic_sni=False, block_dot=False
        )
        self.assertEqual(build_windivert_filter(cfg_none), "false")

        cfg_dot = PacketFilterConfig(block_dot=True)
        self.assertIn("tcp.DstPort == 853", build_windivert_filter(cfg_dot))

        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            bl = root / "bl.txt"
            bl.write_text("doubleclick.net\n", encoding="utf-8")
            rules = RuleManager([(bl, "ad")], [])
            stats = StatsStore(root / "stats.json")
            proc = PacketProcessor(rules, stats, cfg_dot, dns_cache=DnsPacketCache())

            # DoT porta 853 bloqueado
            dot_pkt = make_ipv4_tcp("192.168.1.5", "1.1.1.1", 50000, 853, make_tls_client_hello("1dot1dot1dot1.cloudflare-dns.com"))
            dec_dot = proc.process_packet(dot_pkt, outbound=True)
            self.assertFalse(dec_dot.pass_original)
            self.assertEqual(dec_dot.protocol, "dot")

            # IPv6 TLS SNI bloqueado
            v6_tls = make_ipv6_tcp("2001:db8::1", "2001:db8::2", 50001, 443, make_tls_client_hello("ads.doubleclick.net"))
            dec_v6 = proc.process_packet(v6_tls, outbound=True)
            self.assertFalse(dec_v6.pass_original)
            self.assertTrue(dec_v6.injections[0].is_ipv6)

            # Fail-open se process_packet lançar erro inesperado
            from qproxy.windivert import WinDivertAddress

            class _BoomHandle:
                def __init__(self):
                    self.items = [(b"bad", True)]
                    self.sent = []
                def configure_queues(self):
                    pass
                def recv(self):
                    if not self.items:
                        return None
                    raw, out = self.items.pop(0)
                    a = WinDivertAddress()
                    a.Outbound = 1 if out else 0
                    return raw, a
                def send(self, raw, addr, recalc_checksums=False):
                    self.sent.append((raw, recalc_checksums))
                    return True
                def shutdown(self):
                    pass
                def close(self):
                    pass

            boom = _BoomHandle()
            with patch.object(proc, "process_packet", side_effect=RuntimeError("boom")):
                wf = WindowsPacketFilter(root / "WinDivert.dll", proc, cfg_dot, handle_factory=lambda *_: boom)
                wf.start()
                wf._thread.join(timeout=2)
                wf.stop()
            self.assertEqual(boom.sent, [(b"bad", False)])


class DnsAndProxyEdgeCaseTests(unittest.IsolatedAsyncioTestCase):
    async def test_dns_tcp_and_upstream_racing_fallback(self):
        from qproxy.config import DnsServerConfig

        loop = asyncio.get_running_loop()
        # Upstream que responde normalmente
        class _GoodDns(asyncio.DatagramProtocol):
            def connection_made(self, t):
                self.t = t
            def datagram_received(self, data, addr):
                from qproxy.packet_parser import parse_dns_query
                q = parse_dns_query(data)
                if q:
                    self.t.sendto(make_dns_a_response(q.qname, txid=q.txid), addr)

        t_good, _ = await loop.create_datagram_endpoint(_GoodDns, local_addr=("127.0.0.1", 0))
        good_port = t_good.get_extra_info("sockname")[1]

        # Porta UDP fechada/morta para testar corrida com fallback no 2º upstream
        dead_sock = await loop.create_datagram_endpoint(asyncio.DatagramProtocol, local_addr=("127.0.0.1", 0))
        dead_port = dead_sock[0].get_extra_info("sockname")[1]
        dead_sock[0].close()

        with tempfile.TemporaryDirectory() as d:
            bl = Path(d) / "bl.txt"
            bl.write_text("ads.test\n", encoding="utf-8")
            rules = RuleManager([(bl, "ad")], [])
            stats = StatsStore(Path(d) / "stats.json")
            cfg = DnsServerConfig(
                enabled=True,
                listen_host="127.0.0.1",
                listen_port=0,
                upstreams=[f"127.0.0.1:{dead_port}", f"127.0.0.1:{good_port}"],
                upstream_timeout_seconds=1.5,
            )
            srv = LocalDnsServer(cfg, rules, stats, DnsPacketCache())
            await srv.start()
            try:
                # Consulta via TCP (2-byte prefix)
                q = make_dns_query("ok.example.org", txid=0x7777)
                r, w = await asyncio.open_connection("127.0.0.1", srv.bound_port)
                w.write(struct.pack("!H", len(q)) + q)
                await w.drain()
                len_b = await asyncio.wait_for(r.readexactly(2), timeout=3)
                resp = await asyncio.wait_for(r.readexactly(struct.unpack("!H", len_b)[0]), timeout=3)
                self.assertEqual(parse_dns_response(resp).txid, 0x7777)
                w.close()
                await w.wait_closed()

                # Pausa desabilita bloqueio no DNS local
                rules.pause_for(30)
                resp_paused = await srv.resolve_payload(make_dns_query("ads.test", txid=0x8888))
                self.assertIsNotNone(resp_paused)
                self.assertFalse(resp_paused.endswith(b"\x00\x00\x00\x00"))
            finally:
                await srv.stop()
                t_good.close()

    async def test_proxy_connect_block_tunnel_431_and_502(self):
        self.assertEqual(_parse_host_port("[::1]:8443", 443), ("::1", 8443))
        self.assertEqual(_parse_host_port("[2001:db8::1]", 443), ("2001:db8::1", 443))
        with self.assertRaises(ValueError):
            _rewrite_http_request("GET", "/no-host", "HTTP/1.1", [])

        async def echo_upstream(reader, writer):
            data = await reader.read(64)
            writer.write(b"ECHO:" + data)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        up = await asyncio.start_server(echo_upstream, "127.0.0.1", 0)
        up_port = up.sockets[0].getsockname()[1]

        with tempfile.TemporaryDirectory() as d:
            bl = Path(d) / "bl.txt"
            bl.write_text("blocked-https.test\n", encoding="utf-8")
            rules = RuleManager([(bl, "ad")], [])
            stats = StatsStore(Path(d) / "stats.json")
            host_cache = HostAddressCache()
            host_cache.put("cached.example.test", up_port, ["127.0.0.1"])
            proxy = ProxyServer(Config(), rules, stats, host_cache=host_cache)
            srv = await asyncio.start_server(proxy.handle_client, "127.0.0.1", 0, limit=64 * 1024 + 8192)
            p_port = srv.sockets[0].getsockname()[1]
            try:
                # 1. CONNECT bloqueado -> 403
                r1, w1 = await asyncio.open_connection("127.0.0.1", p_port)
                w1.write(b"CONNECT blocked-https.test:443 HTTP/1.1\r\nHost: blocked-https.test:443\r\n\r\n")
                await w1.drain()
                res1 = await asyncio.wait_for(r1.read(), timeout=3)
                self.assertIn(b"403 Blocked by Qproxy", res1)
                w1.close()
                await w1.wait_closed()

                # 2. CONNECT permitido via HostAddressCache (sem depender de DNS externo) -> túnel bidirecional
                r2, w2 = await asyncio.open_connection("127.0.0.1", p_port)
                w2.write(
                    f"CONNECT cached.example.test:{up_port} HTTP/1.1\r\nHost: cached.example.test:{up_port}\r\n\r\n".encode("ascii")
                )
                await w2.drain()
                established = await asyncio.wait_for(r2.readuntil(b"\r\n\r\n"), timeout=3)
                self.assertIn(b"200 Connection Established", established)
                w2.write(b"ping")
                await w2.drain()
                w2.write_eof()
                echoed = await asyncio.wait_for(r2.read(), timeout=3)
                self.assertEqual(echoed, b"ECHO:ping")
                w2.close()
                await w2.wait_closed()

                # 3. Cabeçalho inválido -> 502 Bad Gateway
                r3, w3 = await asyncio.open_connection("127.0.0.1", p_port)
                w3.write(b"BADLINE\r\n\r\n")
                await w3.drain()
                res3 = await asyncio.wait_for(r3.read(), timeout=3)
                self.assertIn(b"502 Bad Gateway", res3)
                w3.close()
                await w3.wait_closed()
            finally:
                srv.close()
                await srv.wait_closed()
                up.close()
                await up.wait_closed()


class DashboardBrowserSetupAndUpdaterEdgeTests(unittest.TestCase):
    def test_dashboard_html_pause_resume_update_and_errors(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            rules = RuleManager([], [root / "wl.txt"], manual_blocklist_path=root / "m.txt")
            stats = StatsStore(root / "stats.json")
            updater = BlocklistUpdater([], root / "remote")
            dash = DashboardServer("127.0.0.1", 0, stats, rules, updater, token="secret")
            dash.start()
            try:
                base = f"http://127.0.0.1:{dash.port}"
                with urlopen(base + "/", timeout=3) as resp:
                    html = resp.read().decode("utf-8")
                    self.assertIn("Qproxy V4.0", html)
                    self.assertIn("Content-Security-Policy", resp.headers)

                with self.assertRaises(HTTPError) as e404:
                    urlopen(base + "/nao-existe", timeout=3)
                self.assertEqual(e404.exception.code, 404)

                with self.assertRaises(HTTPError) as e400:
                    urlopen(base + "/api/rules?page=0", timeout=3)
                self.assertEqual(e400.exception.code, 400)

                def post(route: str, body: bytes = b"{}"):
                    req = Request(
                        base + route,
                        data=body,
                        headers={"Content-Type": "application/json", "X-Qproxy-Admin": "secret"},
                        method="POST",
                    )
                    with urlopen(req, timeout=3) as resp:
                        return json.load(resp)

                self.assertTrue(post("/api/pause")["rules"]["blocking_paused"])
                self.assertFalse(post("/api/resume")["rules"]["blocking_paused"])
                self.assertTrue(post("/api/update-lists")["ok"])

                with self.assertRaises(HTTPError) as bad_json:
                    post("/api/blocklist", b"{invalid")
                self.assertEqual(bad_json.exception.code, 400)

                with self.assertRaises(HTTPError) as post_404:
                    post("/api/unknown")
                self.assertEqual(post_404.exception.code, 404)
            finally:
                dash.stop()

    def test_browser_setup_all_branches_and_print(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "browser_extension").mkdir()
            (root / "browser_extension" / "manifest.json").write_text('{"manifest_version":3}', encoding="utf-8")
            browsers = [
                BrowserInfo("chrome", "Google Chrome", root / "chrome.exe"),
                BrowserInfo("edge", "Microsoft Edge", root / "msedge.exe"),
                BrowserInfo("brave", "Brave", root / "brave.exe"),
                BrowserInfo("firefox", "Mozilla Firefox", root / "firefox.exe"),
            ]

            with patch("qproxy.browser_setup.detect_installed_browsers", return_value=browsers):
                # auto_install = False
                _, res_off, pkgs = setup_browser_companion(root, BrowserCompanionConfig(auto_install=False))
                self.assertTrue(all(r.status == "detected" for r in res_off))

                # sem IDs/XPI
                _, res_wait, _ = setup_browser_companion(root, BrowserCompanionConfig())
                self.assertEqual(res_wait[0].status, "publication_required")
                self.assertEqual(res_wait[3].status, "signature_required")

                # managed_policy_install = False com IDs configurados
                cfg_ready = BrowserCompanionConfig(
                    managed_policy_install=False,
                    chrome_extension_id="aaaa",
                    edge_extension_id="bbbb",
                    brave_extension_id="cccc",
                    firefox_signed_xpi="data/browser/signed.xpi",
                )
                _, res_ready, _ = setup_browser_companion(root, cfg_ready)
                self.assertTrue(all(r.status == "distribution_ready" for r in res_ready))

                # IS_WINDOWS=True + políticas gravadas no winreg simulado
                fake_reg = _FakeWinReg()
                fake_reg.CreateKeyEx = lambda *_args: fake_reg._KeyCtx(fake_reg.store)
                fake_reg.EnumValue = MagicMock(side_effect=OSError("end"))
                fake_reg.REG_MULTI_SZ = 7
                fake_reg.KEY_WRITE = 2
                cfg_on = BrowserCompanionConfig(
                    managed_policy_install=True,
                    chrome_extension_id="aaaa",
                    edge_extension_id="bbbb",
                    brave_extension_id="cccc",
                    firefox_signed_xpi="https://example.test/qproxy.xpi",
                )
                with (
                    patch("qproxy.browser_setup.IS_WINDOWS", True),
                    patch("qproxy.browser_setup.winreg", fake_reg, create=True),
                ):
                    _, res_on, _ = setup_browser_companion(root, cfg_on)
                    self.assertTrue(all(r.status == "install_configured" for r in res_on))
                    self.assertIn("ExtensionSettings", fake_reg.store)

                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    print_browser_setup(res_on, pkgs)
                self.assertIn("Google Chrome", buf.getvalue())
                self.assertIn("Mozilla Firefox", buf.getvalue())

    def test_updater_parallel_errors_and_config_ignore_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg_p = root / "cfg.json"
            cfg_p.write_text(json.dumps({"unknown_future_key": 123, "mode": "dns"}), encoding="utf-8")
            cfg = Config.load(cfg_p)
            self.assertEqual(cfg.mode, "dns")

            s1 = RemoteListSource("S1", "https://example.test/s1", "ad", min_rules=10)
            s2 = RemoteListSource("S2", "https://example.test/s2", "tracker", min_rules=10)
            updater = BlocklistUpdater([s1, s2], root / "cache")

            # Antes do download -> status mostra Aguardando primeiro download
            st0 = updater.status()
            self.assertFalse(st0[0]["ok"])
            self.assertIn("Aguardando", st0[0]["error"])

            # browser_rules corrompido retorna estrutura vazia segura
            (root / "cache").mkdir(parents=True, exist_ok=True)
            updater.browser_rules_path.write_text("{corrupt", encoding="utf-8")
            self.assertEqual(updater.browser_rules(), {"version": 1, "rules": []})


if __name__ == "__main__":
    unittest.main()
