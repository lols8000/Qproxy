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
