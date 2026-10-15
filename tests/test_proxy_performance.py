import asyncio
import threading
import time
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from qproxy.blocklist import DomainMatcher, RuleManager
from qproxy.config import Config
from qproxy.proxy import ProxyServer
from qproxy.stats import StatsStore


class AtomicReloadTests(unittest.TestCase):
    def test_evaluation_does_not_wait_for_large_list_rebuild(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.txt"
            source.write_text("ads.example.test\n", encoding="utf-8")
            rules = RuleManager([(source, "ad")], [])
            started = threading.Event()
            release = threading.Event()
            original_load = DomainMatcher.load_file

            def slow_load(matcher, *args, **kwargs):
                started.set()
                release.wait(2)
                return original_load(matcher, *args, **kwargs)

            with patch.object(DomainMatcher, "load_file", slow_load):
                worker = threading.Thread(target=rules.reload, daemon=True)
                worker.start()
                try:
                    self.assertTrue(started.wait(timeout=2))
                    begin = time.monotonic()
                    # The old rules must keep working while a new set builds.
                    self.assertTrue(rules.is_blocked("ads.example.test"))
                    self.assertLess(time.monotonic() - begin, 0.5)
                finally:
                    release.set()
                    worker.join(timeout=3)
                self.assertFalse(worker.is_alive())


class UpstreamConnectTests(unittest.IsolatedAsyncioTestCase):
    async def test_happy_eyeballs_and_connect_metrics(self):
        async def upstream(reader, writer):
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(upstream, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            with tempfile.TemporaryDirectory() as directory:
                stats = StatsStore(Path(directory) / "stats.json")
                proxy = ProxyServer(Config(), RuleManager([], []), stats)
                real_connect = asyncio.open_connection
                calls = []

                async def traced_connect(*args, **kwargs):
                    calls.append(kwargs.copy())
                    return await real_connect(*args, **kwargs)

                with patch("qproxy.proxy.asyncio.open_connection", side_effect=traced_connect):
                    reader, writer = await proxy._open_upstream("127.0.0.1", port)
                self.assertIsNotNone(reader)
                writer.close()
                await writer.wait_closed()
                self.assertEqual(len(calls), 1)
                self.assertEqual(calls[0]["happy_eyeballs_delay"], 0.25)
                self.assertEqual(calls[0]["interleave"], 1)
                snapshot = stats.snapshot()
                self.assertEqual(snapshot["connect_samples"], 1)
                self.assertGreaterEqual(snapshot["average_connect_ms"], 0)
                self.assertEqual(snapshot["slow_connects"], 0)
        finally:
            server.close()
            await server.wait_closed()


if __name__ == "__main__":
    unittest.main()
