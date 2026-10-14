import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from qproxy.config import RemoteListSource
from qproxy.updater import BlocklistUpdater


class _FakeResponse:
    def __init__(self, payload: bytes):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def read(self, size=-1):
        return self.payload if size < 0 else self.payload[:size]


class UpdaterTests(unittest.TestCase):
    def test_refresh_keeps_remote_list(self):
        payload = ("! EasyList-like test\n" + "||ads.example.com^\n" * 20).encode()
        with tempfile.TemporaryDirectory() as d:
            source = RemoteListSource("Test", "https://example.invalid/list.txt", "ad", "test.txt")
            updater = BlocklistUpdater([source], d)
            with patch("qproxy.updater.urlopen", return_value=_FakeResponse(payload)):
                result = updater.refresh()
            self.assertTrue(result[0].ok)
            self.assertEqual((Path(d) / "test.txt").read_bytes(), payload)

    def test_rejects_invalid_remote_list_and_keeps_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            source = RemoteListSource(
                "Reliable", "https://example.invalid/hosts.txt",
                "ad", "reliable.txt", min_rules=20,
            )
            path = Path(directory) / "reliable.txt"
            payload = ("0.0.0.0 old.example.com\n" * 30).encode("utf-8")
            path.write_bytes(payload)
            updater = BlocklistUpdater([source], directory)
            bad = ("<!doctype html><h1>not a list</h1>" * 10).encode("utf-8")
            with patch("qproxy.updater.urlopen", return_value=_FakeResponse(bad)):
                result = updater.refresh()
            self.assertFalse(result[0].ok)
            self.assertTrue(result[0].cached)
            self.assertEqual(path.read_bytes(), payload)
            self.assertTrue(updater.status()[0]["updated_at"])

    def test_rejects_sudden_80_percent_list_shrink(self):
        with tempfile.TemporaryDirectory() as directory:
            source = RemoteListSource("Reliable", "https://example.invalid/hosts.txt", "ad", "list.txt", min_rules=10)
            path = Path(directory) / "list.txt"
            path.write_text("0.0.0.0 old.example.test\n" * 100, encoding="utf-8")
            updater = BlocklistUpdater([source], directory)
            small = ("0.0.0.0 new.example.test\n" * 10).encode("utf-8")
            with patch("qproxy.updater.urlopen", return_value=_FakeResponse(small)):
                result = updater.refresh()
            self.assertFalse(result[0].ok)
            self.assertIn("queda anormal", result[0].error)
            self.assertIn("old.example.test", path.read_text(encoding="utf-8"))

    def test_failed_update_does_not_replace_cache(self):
        with tempfile.TemporaryDirectory() as d:
            source = RemoteListSource("Test", "https://example.invalid/list.txt", "ad", "test.txt")
            path = Path(d) / "test.txt"
            path.write_text("known-good", encoding="utf-8")
            updater = BlocklistUpdater([source], d)
            with patch("qproxy.updater.urlopen", side_effect=OSError("offline")):
                result = updater.refresh()
            self.assertFalse(result[0].ok)
            self.assertEqual(path.read_text(encoding="utf-8"), "known-good")


if __name__ == "__main__":
    unittest.main()
