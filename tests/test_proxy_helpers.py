import unittest

from qproxy.proxy import _parse_host_port, _rewrite_http_request


class ProxyHelperTests(unittest.TestCase):
    def test_parse_host_port(self):
        self.assertEqual(_parse_host_port("example.com:8443", 443), ("example.com", 8443))
        self.assertEqual(_parse_host_port("example.com", 443), ("example.com", 443))

    def test_rewrite_absolute_uri(self):
        host, port, raw = _rewrite_http_request(
            "GET",
            "http://example.com/path?q=1",
            "HTTP/1.1",
            [("Host", "example.com"), ("Proxy-Connection", "keep-alive")],
        )
        self.assertEqual(host, "example.com")
        self.assertEqual(port, 80)
        text = raw.decode("iso-8859-1")
        self.assertTrue(text.startswith("GET /path?q=1 HTTP/1.1\r\n"))
        self.assertNotIn("Proxy-Connection", text)
        self.assertIn("Connection: close", text)


if __name__ == "__main__":
    unittest.main()
