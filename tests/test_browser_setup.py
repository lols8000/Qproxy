import json
import tempfile
import unittest
from pathlib import Path
import zipfile

from qproxy.browser_setup import (
    _CHROMIUM_POLICY_PATHS,
    build_extension_packages,
    detect_installed_browsers,
)
from qproxy.config import BrowserCompanionConfig


class BrowserSetupTests(unittest.TestCase):
    def test_detects_all_four_supported_browsers(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            candidates = {}
            names = {
                "chrome": "chrome.exe",
                "edge": "msedge.exe",
                "firefox": "firefox.exe",
                "brave": "brave.exe",
            }

            for key, filename in names.items():
                path = root / key / filename
                path.parent.mkdir()
                path.write_bytes(b"fake")
                candidates[key] = [path]

            browsers = detect_installed_browsers(
                env={},
                extra_candidates=candidates,
                use_registry=False,
            )

            self.assertEqual(
                {browser.key for browser in browsers},
                {"chrome", "edge", "firefox", "brave"},
            )

    def test_builds_zip_and_xpi(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            ext = root / "browser_extension"
            ext.mkdir()
            (ext / "manifest.json").write_text(
                json.dumps(
                    {
                        "manifest_version": 3,
                        "name": "Qproxy",
                        "version": "1.0",
                    }
                ),
                encoding="utf-8",
            )
            (ext / "content.js").write_text(
                "console.log('ok')",
                encoding="utf-8",
            )

            zip_path, xpi_path = build_extension_packages(
                root,
                root / "out",
            )

            self.assertTrue(zip_path.is_file())
            self.assertTrue(xpi_path.is_file())

            with zipfile.ZipFile(zip_path) as archive:
                self.assertIn(
                    "manifest.json",
                    archive.namelist(),
                )
                self.assertIn(
                    "content.js",
                    archive.namelist(),
                )

    def test_policy_paths_cover_chrome_edge_and_brave(self):
        self.assertEqual(
            set(_CHROMIUM_POLICY_PATHS),
            {"chrome", "edge", "brave"},
        )
        self.assertIn(
            r"Google\Chrome",
            _CHROMIUM_POLICY_PATHS["chrome"],
        )
        self.assertIn(
            r"Microsoft\Edge",
            _CHROMIUM_POLICY_PATHS["edge"],
        )
        self.assertIn(
            r"BraveSoftware\Brave",
            _CHROMIUM_POLICY_PATHS["brave"],
        )

    def test_browser_config_defaults_target_all_four(self):
        config = BrowserCompanionConfig()
        self.assertTrue(config.auto_detect)
        self.assertTrue(config.auto_install)
        self.assertTrue(config.managed_policy_install)

        self.assertIsNone(config.chrome_extension_id)
        self.assertIsNone(config.edge_extension_id)
        self.assertIsNone(config.brave_extension_id)

        self.assertEqual(
            config.firefox_extension_id,
            "qproxy-youtube@qproxy.local",
        )
        self.assertIsNone(config.firefox_signed_xpi)

    def test_legacy_chromium_fields_still_load(self):
        config = BrowserCompanionConfig.from_dict(
            {
                "chromium_extension_id": "legacy-id",
                "chromium_update_url": "https://example.test/update",
            }
        )
        self.assertEqual(
            config.chromium_extension_id,
            "legacy-id",
        )


if __name__ == "__main__":
    unittest.main()
