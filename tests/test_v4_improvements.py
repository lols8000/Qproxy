import asyncio
import gzip
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from qproxy.blocklist import RuleManager, _domain_from_rule, is_ad_url_path
from qproxy.browser_filters import compile_web_rules
from qproxy.config import Config, RemoteListSource
from qproxy.dashboard import DashboardServer
from qproxy.proxy import ProxyServer
from qproxy.stats import StatsStore
from qproxy.updater import BlocklistUpdater


class _FakeGzipResponse:
    def __init__(self, payload: bytes, etag: str = '"v1"'):
        self._raw = gzip.compress(payload)
        self.headers = {"Content-Encoding": "gzip", "ETag": etag}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def read(self, size=-1):
        return self._raw if size < 0 else self._raw[:size]


class V4SystemTests(unittest.TestCase):
    def test_v4_config_example_loads_with_curated_dns_lists(self):
        cfg_path = Path(__file__).resolve().parents[1] / "config.example.json"
        cfg = Config.load(cfg_path)
        self.assertEqual(cfg.mode, "auto")
        self.assertTrue(cfg.packet_filter.enabled)
        self.assertTrue(cfg.packet_filter.filter_quic_sni)
        self.assertTrue(cfg.packet_filter.filter_cname_cloaking)
        names = {s.name for s in cfg.remote_blocklists}
        self.assertIn("HaGeZi Multi PRO", names)
        self.assertIn("AdGuard DNS Filter", names)
        self.assertIn("OISD Big", names)
        self.assertIn("HaGeZi Windows Telemetry", names)

    def test_builtin_blocklist_has_substantial_offline_coverage(self):
        bl = Path(__file__).resolve().parents[1] / "data" / "blocklist.txt"
        rules = RuleManager([(bl, "ad")], [])
        self.assertGreaterEqual(rules.snapshot()["blocked_domains"], 120)
        for domain in ("googleads.g.doubleclick.net", "ads.tiktok.com", "popads.net", "vortex.data.microsoft.com"):
            self.assertTrue(rules.is_blocked(domain), domain)

    def test_enhanced_rule_parser_and_http_path_matching(self):
        self.assertEqual(_domain_from_rule("*.ads.wild.test"), ("ads.wild.test", False))
        self.assertEqual(_domain_from_rule(".tracker.wild.test"), ("tracker.wild.test", False))
        self.assertEqual(_domain_from_rule("0.0.0.0 banner.test # inline"), ("banner.test", False))
        self.assertEqual(_domain_from_rule("||ad.global.test^$important"), ("ad.global.test", False))
        self.assertEqual(_domain_from_rule("||ad.all.test^$all"), ("ad.all.test", False))
        self.assertEqual(_domain_from_rule("@@||safe.test^$important"), ("safe.test", True))
        self.assertEqual(is_ad_url_path("/pagead/js/adsbygoogle.js"), "/pagead/")
        self.assertIsNone(is_ad_url_path("/images/photo.jpg"))

        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            rules = RuleManager([], [root / "wl.txt"], manual_blocklist_path=root / "m.txt")
            self.assertTrue(rules.evaluate_http("www.portal.test", "/pagead/ad.js").blocked)
            self.assertFalse(rules.evaluate_http("www.portal.test", "/artigo/noticia").blocked)
            # Whitelist manual libera inclusive caminhos HTTP
            rules.add_to_whitelist("www.portal.test")
            self.assertFalse(rules.evaluate_http("www.portal.test", "/pagead/ad.js").blocked)

    def test_eval_cache_and_change_listener_invalidation(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            bl = root / "bl.txt"
            bl.write_text("ads.cache.test\n", encoding="utf-8")
            rules = RuleManager([(bl, "ad")], [root / "wl.txt"], manual_blocklist_path=root / "m.txt")
            events = []
            rules.add_change_listener(lambda: events.append("changed"))
            self.assertTrue(rules.is_blocked("ads.cache.test"))
            self.assertTrue(rules.is_blocked("ads.cache.test"))  # cache hit
            rules.add_to_whitelist("ads.cache.test")
            self.assertFalse(rules.is_blocked("ads.cache.test"))
            self.assertGreaterEqual(len(events), 1)

    def test_updater_gzip_and_304_not_modified(self):
        payload = ("! AdGuard DNS test\n" + "||ads.example.test^\n" * 20).encode("utf-8")
        with tempfile.TemporaryDirectory() as d:
            source = RemoteListSource("AdGuard DNS Filter", "https://example.invalid/adguard.txt", "ad", "adguard.txt")
            updater = BlocklistUpdater([source], d)
            with patch("qproxy.updater.urlopen", return_value=_FakeGzipResponse(payload)):
                r1 = updater.refresh()
            self.assertTrue(r1[0].ok)
            self.assertEqual((Path(d) / "adguard.txt").read_bytes(), payload)

            # Segunda chamada com HTTP 304 preserva cache e marca ok=True
            err_304 = HTTPError(source.url, 304, "Not Modified", {}, None)
            with patch("qproxy.updater.urlopen", side_effect=err_304):
                r2 = updater.refresh()
            self.assertTrue(r2[0].ok)
            self.assertTrue(r2[0].cached)
            self.assertGreaterEqual(r2[0].rules, 20)

    def test_compile_web_rules_protects_youtube_and_never_blocks_images(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "adguard.txt"
            p.write_text(
                "||doubleclick.net^\n||googlevideo.com^\n||youtube.com^\n||criteo.com^\n@@||criteo.com^\n",
                encoding="utf-8",
            )
            web = compile_web_rules([p], limit=50)
            domains = [r["condition"]["requestDomains"][0] for r in web]
            self.assertIn("doubleclick.net", domains)
            self.assertNotIn("googlevideo.com", domains)
            self.assertNotIn("youtube.com", domains)
            self.assertNotIn("criteo.com", domains)
            for rule in web:
                self.assertEqual(rule["condition"]["domainType"], "thirdParty")
                self.assertFalse({"image", "media", "main_frame"} & set(rule["condition"]["resourceTypes"]))

    def test_dashboard_engine_status_and_flush_dns_endpoint(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            rules = RuleManager([], [root / "wl.txt"], manual_blocklist_path=root / "m.txt")
            stats = StatsStore(root / "stats.json")
            updater = BlocklistUpdater([], root / "remote")
            flushed = []
            dash = DashboardServer(
                "127.0.0.1",
                0,
                stats,
                rules,
                updater,
                token="tok123",
                engine_status_provider=lambda: {"windivert_active": True, "active_layers": ["DNS", "TLS SNI"]},
                flush_dns_handler=lambda: (flushed.append(True) or True),
            )
            dash.start()
            try:
                base = f"http://127.0.0.1:{dash.port}"
                with urlopen(base + "/api/status", timeout=3) as resp:
                    status = json.load(resp)
                self.assertTrue(status["engine"]["windivert_active"])
                self.assertIn("TLS SNI", status["engine"]["active_layers"])

                req = Request(
                    base + "/api/flush-dns",
                    data=b"{}",
                    headers={"Content-Type": "application/json", "X-Qproxy-Admin": "tok123"},
                    method="POST",
                )
                with urlopen(req, timeout=3) as resp:
                    body = json.load(resp)
                self.assertTrue(body["ok"])
                self.assertEqual(len(flushed), 1)
            finally:
                dash.stop()


class ProxyV4PathTests(unittest.IsolatedAsyncioTestCase):
    async def test_proxy_blocks_http_ad_path_immediately(self):
        with tempfile.TemporaryDirectory() as d:
            rules = RuleManager([], [])
            stats = StatsStore(Path(d) / "stats.json")
            proxy = ProxyServer(Config(), rules, stats)
            srv = await asyncio.start_server(proxy.handle_client, "127.0.0.1", 0)
            port = srv.sockets[0].getsockname()[1]
            try:
                r, w = await asyncio.open_connection("127.0.0.1", port)
                w.write(b"GET http://site.example.test/pagead/js/adsbygoogle.js HTTP/1.1\r\nHost: site.example.test\r\n\r\n")
                await w.drain()
                resp = await asyncio.wait_for(r.read(), timeout=3)
                self.assertIn(b"204 No Content", resp)
                self.assertIn(b"X-Qproxy-Blocked: 1", resp)
                w.close()
                await w.wait_closed()
            finally:
                srv.close()
                await srv.wait_closed()


if __name__ == "__main__":
    unittest.main()
