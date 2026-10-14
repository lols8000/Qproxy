import tempfile
import unittest
from pathlib import Path

from qproxy.blocklist import DomainMatcher, RuleManager, _domain_from_rule, normalize_host


class DomainMatcherTests(unittest.TestCase):
    def test_normalize_host(self):
        self.assertEqual(normalize_host("Ads.Example.COM:443"), "ads.example.com")

    def test_subdomain_is_blocked(self):
        m = DomainMatcher()
        m.add_block("doubleclick.net")
        self.assertTrue(m.is_blocked("securepubads.doubleclick.net"))
        self.assertFalse(m.is_blocked("notdoubleclick.net"))

    def test_whitelist_wins(self):
        m = DomainMatcher()
        m.add_block("example.com")
        m.add_allow("safe.example.com")
        self.assertTrue(m.is_blocked("ads.example.com"))
        self.assertFalse(m.is_blocked("safe.example.com"))
        self.assertFalse(m.is_blocked("sub.safe.example.com"))

    def test_hosts_and_adblock_rules(self):
        content = """
0.0.0.0 ads.one.test
127.0.0.1 tracker.two.test
||ads.three.test^
@@||safe.three.test^
"""
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "rules.txt"
            p.write_text(content, encoding="utf-8")
            m = DomainMatcher()
            m.load_file(p)
            self.assertTrue(m.is_blocked("ads.one.test"))
            self.assertTrue(m.is_blocked("sub.tracker.two.test"))
            self.assertTrue(m.is_blocked("ads.three.test"))
            self.assertFalse(m.is_blocked("safe.three.test"))

    def test_resource_scoped_adblock_rules_do_not_block_entire_image_host(self):
        scoped = (
            "||images.example.com^$image",
            "||images.example.com^$script,third-party",
            "||images.example.com/banner.jpg^",
            "||images.example.com/path^$third-party",
            "@@||images.example.com^$document",
            "https://images.example.com/banner.jpg",
            "|https://images.example.com/banner.jpg|",
        )
        for rule in scoped:
            with self.subTest(rule=rule):
                self.assertEqual(_domain_from_rule(rule)[0], None)

    def test_host_only_rules_still_block_ads(self):
        m = DomainMatcher()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "list.txt"
            path.write_text(
                "||ads.example.net^\n"
                "||images.example.net^$image\n"
                "https://static.example.net/sponsor.jpg\n",
                encoding="utf-8",
            )
            m.load_file(path)
        self.assertTrue(m.is_blocked("cdn.ads.example.net"))
        self.assertFalse(m.is_blocked("images.example.net"))
        self.assertFalse(m.is_blocked("static.example.net"))

    def test_pause_and_resume_blocking(self):
        with tempfile.TemporaryDirectory() as d:
            blocked = Path(d) / "blocked.txt"
            blocked.write_text("ads.example.com\n", encoding="utf-8")
            rules = RuleManager([(blocked, "ad")], [])
            self.assertTrue(rules.is_blocked("ads.example.com"))

            rules.pause_for(30)
            self.assertTrue(rules.snapshot()["blocking_paused"])
            self.assertFalse(rules.is_blocked("ads.example.com"))

            rules.resume()
            self.assertFalse(rules.snapshot()["blocking_paused"])
            self.assertTrue(rules.is_blocked("ads.example.com"))

            with self.assertRaises(ValueError):
                rules.pause_for(3600)

    def test_manual_blocklist_persists_and_overrides_remote_exceptions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rules_path = root / "remote.txt"
            whitelist = root / "whitelist.txt"
            manual = root / "manual.txt"
            rules_path.write_text("@@||ads.example.test^\n||other.example.test^\n", encoding="utf-8")
            rules = RuleManager(
                [(rules_path, "ad")],
                [whitelist],
                ["googlevideo.com"],
                manual,
            )
            self.assertFalse(rules.is_blocked("ads.example.test"))
            rules.add_to_blocklist("ads.example.test")
            self.assertTrue(rules.is_blocked("sub.ads.example.test"))
            self.assertEqual(rules.evaluate("ads.example.test").category, "manual")
            self.assertIn("ads.example.test", manual.read_text(encoding="utf-8"))
            rules.reload()
            self.assertTrue(rules.is_blocked("ads.example.test"))
            with self.assertRaisesRegex(ValueError, "protegido"):
                rules.add_to_blocklist("rr.googlevideo.com")
            rules.add_to_whitelist("ads.example.test")
            self.assertFalse(rules.is_blocked("ads.example.test"))
            self.assertTrue(rules.is_blocked("other.example.test"))
            rules.remove_from_whitelist("ads.example.test")
            self.assertTrue(rules.is_blocked("ads.example.test"))
            rules.remove_from_blocklist("ads.example.test")
            self.assertFalse(rules.is_blocked("ads.example.test"))

    def test_rules_listing_search_and_pagination(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            list_path = root / "list.txt"
            list_path.write_text("ads.one.test\nads.two.test\ntracker.three.test\n", encoding="utf-8")
            rules = RuleManager([(list_path, "tracker")], [], manual_blocklist_path=root / "manual.txt")
            rules.add_to_blocklist("promo.four.test")
            result = rules.list_rules("ads.", page=1, limit=1)
            self.assertEqual(result["total"], 2)
            self.assertEqual(len(result["items"]), 1)
            self.assertEqual(result["items"][0]["domain"], "ads.one.test")
            self.assertEqual(rules.list_rules(scope="manual")["total"], 1)
            self.assertEqual(rules.list_rules(scope="manual")["items"][0]["source"], "Você")
            self.assertEqual(rules.list_rules(page=2, limit=2)["total"], 4)
            with self.assertRaises(ValueError):
                rules.list_rules(page=0)

    def test_static_compatibility_allowlist_wins_remote_block(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            blocked = root / "remote.txt"
            user_allow = root / "whitelist.txt"
            blocked.write_text(
                "||googlevideo.com^\n||youtube.com^\n||ads.example.test^\n",
                encoding="utf-8",
            )
            user_allow.write_text("", encoding="utf-8")
            rules = RuleManager(
                [(blocked, "ad")],
                [user_allow],
                ["googlevideo.com", "youtube.com"],
            )
            self.assertFalse(rules.is_blocked("rr1---sn.example.googlevideo.com"))
            self.assertFalse(rules.is_blocked("www.youtube.com"))
            self.assertTrue(rules.is_blocked("ads.example.test"))


if __name__ == "__main__":
    unittest.main()
