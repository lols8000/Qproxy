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

    def read(self):
        return self.payload


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
