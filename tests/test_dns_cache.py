import time
import unittest
from unittest.mock import patch

from qproxy.dns_cache import DnsPacketCache, HostAddressCache


class DnsPacketCacheTests(unittest.TestCase):
    def test_put_get_ttl_clamping_and_expiration(self):
        clock = [100.0]
        with patch("qproxy.dns_cache.monotonic", side_effect=lambda: clock[0]):
            cache = DnsPacketCache(max_entries=10, min_ttl=30, max_ttl=600)
            payload = b"\x00\x01\x81\x80" + b"\x00" * 16

            # TTL abaixo de min_ttl é elevado para 30s
            cache.put("Ads.Example.COM.", 1, payload, ttl=5)
            hit = cache.get("ads.example.com", 1)
            self.assertIsNotNone(hit)
            self.assertEqual(hit[0], payload)
            self.assertEqual(hit[1], 30)

            # Avança 20s -> remaining = 10s
            clock[0] = 120.0
            hit2 = cache.get("ads.example.com", 1)
            self.assertEqual(hit2[1], 10)

            # Avança além de 30s -> expirado -> miss
            clock[0] = 131.0
            self.assertIsNone(cache.get("ads.example.com", 1))

            # TTL acima de max_ttl é limitado a 600s
            cache.put("long.example.com", 28, payload, ttl=99999)
            self.assertEqual(cache.get("long.example.com", 28)[1], 600)

            stats = cache.stats()
            self.assertEqual(stats["hits"], 3)
            self.assertEqual(stats["misses"], 1)
            self.assertEqual(stats["hit_rate_pct"], 75.0)

    def test_lru_eviction_and_domain_invalidation(self):
        # DnsPacketCache impõe mínimo de 64 entradas; enche 64 e verifica LRU
        cache = DnsPacketCache(max_entries=64, min_ttl=10, max_ttl=60)
        payload = b"\x00\x01\x81\x80" + b"\x00" * 12
        for i in range(64):
            cache.put(f"host{i}.example.test", 1, payload, 60)

        # Acessa host0 para torná-lo mais recente que host1
        self.assertIsNotNone(cache.get("host0.example.test", 1))
        cache.put("host64.example.test", 1, payload, 60)

        self.assertIsNotNone(cache.get("host0.example.test", 1))
        self.assertIsNone(cache.get("host1.example.test", 1))

        # Invalidar domínio remove subdomínios, mas preserva domínios irmãos
        cache.put("sub.target.test", 1, payload, 60)
        cache.put("target.test", 28, payload, 60)
        cache.put("nottarget.test", 1, payload, 60)
        removed = cache.invalidate_domain("target.test")
        self.assertEqual(removed, 2)
        self.assertIsNone(cache.get("sub.target.test", 1))
        self.assertIsNone(cache.get("target.test", 28))
        self.assertIsNotNone(cache.get("nottarget.test", 1))

        # Payloads inválidos/curtos são ignorados com segurança
        cache.put("", 1, payload, 60)
        cache.put("short.test", 1, b"short", 60)
        self.assertIsNone(cache.get("short.test", 1))

        cache.clear()
        self.assertEqual(cache.stats()["entries"], 0)


class HostAddressCacheTests(unittest.TestCase):
    def test_host_cache_put_get_expiry_eviction_and_clear(self):
        clock = [50.0]
        with patch("qproxy.dns_cache.monotonic", side_effect=lambda: clock[0]):
            hcache = HostAddressCache(max_entries=64, ttl_seconds=30.0)
            hcache.put("empty.test", 443, [])
            self.assertIsNone(hcache.get("empty.test", 443))

            for i in range(64):
                hcache.put(f"s{i}.test", 443, [f"10.0.0.{i}"])

            self.assertEqual(hcache.get("s0.test", 443), ["10.0.0.0"])
            hcache.put("s64.test", 443, ["10.0.1.64"])
            self.assertIsNone(hcache.get("s1.test", 443))
            self.assertEqual(hcache.get("s0.test", 443), ["10.0.0.0"])

            # Expiração por TTL
            clock[0] = 85.0
            self.assertIsNone(hcache.get("s0.test", 443))

            hcache.put("live.test", 80, ["1.1.1.1"])
            hcache.clear()
            self.assertIsNone(hcache.get("live.test", 80))


if __name__ == "__main__":
    unittest.main()
