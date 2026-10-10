import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXT = ROOT / "browser_extension"


class BrowserExtensionTests(unittest.TestCase):
    def test_manifest_references_existing_files(self):
        manifest = json.loads((EXT / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["manifest_version"], 3)
        scripts = manifest["content_scripts"][0]
        self.assertIn("*://*.youtube.com/*", scripts["matches"])
        for filename in scripts["js"] + scripts["css"]:
            self.assertTrue((EXT / filename).is_file(), filename)

    def test_network_rules_only_target_youtube_third_party_without_images(self):
        manifest = json.loads((EXT / "manifest.json").read_text(encoding="utf-8"))
        self.assertIn("declarativeNetRequest", manifest["permissions"])
        resources = manifest["declarative_net_request"]["rule_resources"]
        self.assertEqual(len(resources), 1)
        rules_file = EXT / resources[0]["path"]
        self.assertTrue(rules_file.is_file())
        rules = json.loads(rules_file.read_text(encoding="utf-8"))
        self.assertGreater(len(rules), 5)
        for rule in rules:
            with self.subTest(rule=rule["id"]):
                condition = rule["condition"]
                self.assertEqual(rule["action"]["type"], "block")
                self.assertEqual(condition["initiatorDomains"], ["youtube.com"])
                self.assertEqual(condition["domainType"], "thirdParty")
                self.assertFalse(
                    {"image", "media", "main_frame"} & set(condition["resourceTypes"])
                )

    def test_content_script_uses_active_ad_state(self):
        script = (EXT / "content.js").read_text(encoding="utf-8")
        self.assertIn("ad-showing", script)
        self.assertIn("ad-interrupting", script)
        self.assertNotIn('".ytp-ad-module"', script)
        self.assertIn("function restore()", script)
        self.assertIn('player.classList.contains("ad-showing")', script)
        self.assertNotIn("MutationObserver", script)


if __name__ == "__main__":
    unittest.main()
