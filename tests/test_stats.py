import tempfile
import unittest
from pathlib import Path

from qproxy.stats import StatsStore


class StatsTests(unittest.TestCase):
    def test_counters_and_persistence(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "stats.json"
            stats = StatsStore(path, save_every=99)
            stats.record("ads.example", "blocked", "https", "ad")
            stats.record("tracker.example", "blocked", "https", "tracker")
            stats.record("safe.example", "allowed", "http")
            stats.add_bytes(2048)
            snap = stats.snapshot()
            self.assertEqual(snap["blocked_requests"], 2)
            self.assertEqual(snap["blocked_ads"], 1)
            self.assertEqual(snap["blocked_trackers"], 1)
            self.assertEqual(snap["allowed_requests"], 1)
            self.assertEqual(snap["bytes_relayed"], 2048)
            stats.save()
            restored = StatsStore(path)
            self.assertEqual(restored.snapshot()["blocked_requests"], 2)


if __name__ == "__main__":
    unittest.main()
