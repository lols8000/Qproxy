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
