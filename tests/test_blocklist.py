import tempfile
import unittest
from pathlib import Path

from qproxy.blocklist import DomainMatcher, normalize_host


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


if __name__ == "__main__":
    unittest.main()
