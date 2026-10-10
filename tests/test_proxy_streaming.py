import asyncio
import tempfile
import unittest
from pathlib import Path

from qproxy.blocklist import RuleManager
from qproxy.config import Config
from qproxy.proxy import ProxyServer
from qproxy.stats import StatsStore


class ProxyStreamingTests(unittest.IsolatedAsyncioTestCase):
    async def test_half_closed_request_still_receives_entire_image(self):
        # Regression: FIRST_COMPLETED cancelled the response pump
        # immediately after the client finished sending its request.
        image_bytes = bytes(range(256)) * 1024

        async def upstream(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            header = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: image/png\r\n"
                + f"Content-Length: {len(image_bytes)}\r\n".encode("ascii")
                + b"Connection: close\r\n\r\n"
            )
            writer.write(header + image_bytes[:1024])
            await writer.drain()
            await asyncio.sleep(0.06)
            writer.write(image_bytes[1024:])
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        upstream_server = await asyncio.start_server(upstream, "127.0.0.1", 0)
        upstream_port = upstream_server.sockets[0].getsockname()[1]

        with tempfile.TemporaryDirectory() as directory:
            rules = RuleManager([], [])
            stats = StatsStore(Path(directory) / "stats.json")
            proxy = ProxyServer(Config(), rules, stats)
            proxy_server = await asyncio.start_server(
                proxy.handle_client, "127.0.0.1", 0
            )
            proxy_port = proxy_server.sockets[0].getsockname()[1]
            client_writer = None
            try:
                reader, client_writer = await asyncio.open_connection(
                    "127.0.0.1", proxy_port
                )
                client_writer.write(
                    (
                        f"GET http://127.0.0.1:{upstream_port}/image.png HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{upstream_port}\r\n"
                        "Connection: close\r\n\r\n"
                    ).encode("ascii")
                )
                await client_writer.drain()
                client_writer.write_eof()
                response = await asyncio.wait_for(reader.read(), timeout=5)

                header, received = response.split(b"\r\n\r\n", 1)
                self.assertIn(b"200 OK", header)
                self.assertEqual(received, image_bytes)
            finally:
                if client_writer is not None:
                    client_writer.close()
                    await client_writer.wait_closed()
                proxy_server.close()
                await proxy_server.wait_closed()

        upstream_server.close()
        await upstream_server.wait_closed()


if __name__ == "__main__":
    unittest.main()
