import json
import tempfile
import unittest
from pathlib import Path

from qproxy.browser_filters import _parse_rule, compile_youtube_rules
from qproxy.config import RemoteListSource
from qproxy.updater import BlocklistUpdater


class BrowserFiltersTests(unittest.TestCase):
    def test_specific_url_rules_are_not_widened(self):
        parsed = _parse_rule("||ads.example.net/banner^$domain=youtube.com")
        self.assertIsNone(parsed)  # Unsafe separator/path ambiguity
        parsed = _parse_rule("||ads.example.net/banner$domain=youtube.com")
        self.assertIsNotNone(parsed)
        condition, allow, targeted = parsed
        self.assertEqual(condition["urlFilter"], "||ads.example.net/banner")
        self.assertTrue(targeted)
        self.assertFalse(allow)

    def test_domain_scope_with_pipes_is_not_mistaken_for_url_syntax(self):
        parsed = _parse_rule(
            "||ads.vendor.test^$domain=youtube.com|music.youtube.com,script"
        )
        self.assertIsNotNone(parsed)
        condition, allow, targeted = parsed
        self.assertEqual(condition["requestDomains"], ["ads.vendor.test"])
        self.assertEqual(condition["resourceTypes"], ["script"])
        self.assertTrue(targeted)
        self.assertFalse(allow)
        self.assertIsNone(
            _parse_rule("||ads.vendor.test^$domain=youtube.com|other.com,script")
        )

    def test_protects_youtube_video_and_images(self):
        for line in [
            "||youtube.com^", "||googlevideo.com^", "||ytimg.com^",
            "||a.googlevideo.com^", "||youtube.com/watch$domain=youtube.com",
            "||youtubei.googleapis.com^$xmlhttprequest",
            "||ads.example.net^$image",
            "||ads.example.net^$media",
            "||ads.example.net/banner$domain=unrelated.org",
            "||ads.example.net^$script,redirect=noop.js",
        ]:
            with self.subTest(line=line):
                self.assertIsNone(_parse_rule(line))
        self.assertIsNotNone(_parse_rule("||youtube.com/pagead/$domain=youtube.com"))

    def test_compiles_from_verified_files_and_prioritizes_scoped_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            easy = root / "easylist.txt"
            easy.write_text(
                "||network.example.net^\n"
                "||ads.vendor.test^$domain=youtube.com,script\n"
                "@@||safe.vendor.test^$domain=youtube.com,script\n"
                "||www.youtube.com/pagead/$domain=youtube.com\n"
                "||media.googlevideo.com^\n"
                "||image.example.net^$image\n",
                encoding="utf-8",
            )
            rules = compile_youtube_rules([easy], limit=5)
            self.assertTrue(rules)
            self.assertEqual(rules[0]["condition"]["requestDomains"], ["ads.vendor.test"])
            self.assertEqual(rules[1]["action"]["type"], "allow")
            self.assertEqual(rules[1]["priority"], 3)
            self.assertTrue(any(r["condition"].get("urlFilter", "").startswith("||www.youtube.com/pagead/") for r in rules))
            for rule in rules:
                self.assertEqual(rule["condition"]["initiatorDomains"], ["youtube.com"])
                self.assertFalse({"image", "media", "main_frame"} & set(rule["condition"]["resourceTypes"]))
                self.assertFalse(
                    any("googlevideo.com" in host for host in rule["condition"].get("requestDomains", []))
                )

    def test_updater_builds_json_cache_and_keeps_last_good_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = RemoteListSource("EasyList", "https://example.test", "ad", "easylist.txt")
            (root / "easylist.txt").write_text("||ads.example.com^\n", encoding="utf-8")
            updater = BlocklistUpdater([source], root)
            self.assertEqual(updater.build_browser_rules(), 1)
            old = updater.browser_rules()
            self.assertEqual(len(old["rules"]), 1)
            (root / "easylist.txt").unlink()
            self.assertEqual(updater.build_browser_rules(), 0)
            self.assertEqual(updater.browser_rules(), old)


if __name__ == "__main__":
    unittest.main()
