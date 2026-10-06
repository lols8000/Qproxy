import json
import tempfile
import unittest
from pathlib import Path
import zipfile

from qproxy.browser_setup import build_extension_packages, detect_installed_browsers
from qproxy.config import BrowserCompanionConfig


class BrowserSetupTests(unittest.TestCase):
    def test_detects_browser_from_extra_candidate(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            exe = root / "firefox.exe"
            exe.write_bytes(b"fake")
            browsers = detect_installed_browsers(
                env={},
                extra_candidates={"firefox": [exe]},
                use_registry=False,
            )
            self.assertEqual(len(browsers), 1)
            self.assertEqual(browsers[0].key, "firefox")

    def test_builds_zip_and_xpi(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            ext = root / "browser_extension"
            ext.mkdir()
            (ext / "manifest.json").write_text(
                json.dumps({"manifest_version": 3, "name": "Qproxy", "version": "1.0"}),
                encoding="utf-8",
            )
            (ext / "content.js").write_text("console.log('ok')", encoding="utf-8")
            zip_path, xpi_path = build_extension_packages(root, root / "out")
            self.assertTrue(zip_path.is_file())
            self.assertTrue(xpi_path.is_file())
            with zipfile.ZipFile(zip_path) as archive:
                self.assertIn("manifest.json", archive.namelist())
                self.assertIn("content.js", archive.namelist())

    def test_browser_config_defaults_are_safe(self):
        config = BrowserCompanionConfig()
        self.assertTrue(config.auto_detect)
        self.assertTrue(config.auto_install)
        self.assertFalse(config.managed_policy_install)
        self.assertIsNone(config.chrome_extension_id)
        self.assertIsNone(config.firefox_signed_xpi)


if __name__ == "__main__":
    unittest.main()
