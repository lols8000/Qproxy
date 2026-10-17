import json
import tempfile
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from qproxy.blocklist import RuleManager
from qproxy.dashboard import DashboardServer
from qproxy.stats import StatsStore
from qproxy.updater import BlocklistUpdater


class DashboardRulesTests(unittest.TestCase):
    def test_rule_search_and_authenticated_block_actions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            block = root / "blocks.txt"
            block.write_text("ads.vendor.test\ntracker.vendor.test\n", encoding="utf-8")
            rules = RuleManager(
                [(block, "ad")],
                [root / "whitelist.txt"],
                manual_blocklist_path=root / "manual.txt",
            )
            stats = StatsStore(root / "stats.json")
            updater = BlocklistUpdater([], root / "remote")
            dashboard = DashboardServer("127.0.0.1", 0, stats, rules, updater, token="test-private-token")
            dashboard.start()
            try:
                base = f"http://127.0.0.1:{dashboard.port}"

                def get(route):
                    with urlopen(base + route, timeout=3) as response:
                        return json.load(response)

                def post(route, domain, authorized=True):
                    headers = {"Content-Type": "application/json"}
                    if authorized:
                        headers["X-Qproxy-Admin"] = "test-private-token"
                    request = Request(
                        base + route,
                        data=json.dumps({"domain": domain}).encode("utf-8"),
                        headers=headers,
                        method="POST",
                    )
                    with urlopen(request, timeout=3) as response:
                        return json.load(response)

                self.assertEqual(get("/api/rules?search=ads.vendor")["total"], 1)
                with urlopen(base + "/api/browser-rules", timeout=3) as response:
                    self.assertEqual(json.load(response), {"version": 1, "rules": []})
                    self.assertEqual(response.headers["Access-Control-Allow-Origin"], "*")
                with self.assertRaises(HTTPError) as context:
                    post("/api/blocklist", "promo.example.test", authorized=False)
                self.assertEqual(context.exception.code, 403)

                post("/api/blocklist", "promo.example.test")
                self.assertTrue(rules.is_blocked("promo.example.test"))
                self.assertEqual(get("/api/rules?scope=manual")["total"], 1)

                post("/api/whitelist", "ads.vendor.test")
                self.assertFalse(rules.is_blocked("ads.vendor.test"))

                post("/api/blocklist/remove", "promo.example.test")
                self.assertFalse(rules.is_blocked("promo.example.test"))
                post("/api/whitelist/remove", "ads.vendor.test")
                self.assertTrue(rules.is_blocked("ads.vendor.test"))

                self.assertEqual(get("/api/rules?limit=1&page=2")["page"], 2)
            finally:
                dashboard.stop()


if __name__ == "__main__":
    unittest.main()
