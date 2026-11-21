import asyncio
import tempfile
import unittest
from pathlib import Path

from qproxy.blocklist import RuleManager
from qproxy.config import DnsServerConfig
from qproxy.dns_cache import DnsPacketCache
from qproxy.dns_server import DOH_CANARY_DOMAIN, LocalDnsServer
from qproxy.packet_parser import parse_dns_query, parse_dns_response
from qproxy.stats import StatsStore
from tests.test_packet_parser import (
    make_dns_a_response,
    make_dns_cname_response,
    make_dns_query,
)


class _MockUpstreamDns(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.queries: list[str] = []
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        q = parse_dns_query(data)
        if q is None:
            return
        self.queries.append(q.qname)
        if q.qname == "cloaked.site.test":
            resp = make_dns_cname_response(q.qname, "tracker.criteo.com", txid=q.txid)
        else:
            resp = make_dns_a_response(q.qname, ip="93.184.216.34", ttl=180, txid=q.txid)
        self.transport.sendto(resp, addr)


async def _udp_query(host: str, port: int, payload: bytes) -> bytes:
    loop = asyncio.get_running_loop()
    fut: asyncio.Future[bytes] = loop.create_future()

    class _Client(asyncio.DatagramProtocol):
        def datagram_received(self, data, addr):
            if not fut.done():
                fut.set_result(data)

    transport, _ = await loop.create_datagram_endpoint(_Client, remote_addr=(host, port))
    try:
        transport.sendto(payload)
        return await asyncio.wait_for(fut, timeout=3)
    finally:
        transport.close()


class LocalDnsServerTests(unittest.IsolatedAsyncioTestCase):
    async def test_local_dns_blocks_caches_and_stops_cname_cloaking(self):
        loop = asyncio.get_running_loop()
        upstream_proto = _MockUpstreamDns()
        upstream_transport, _ = await loop.create_datagram_endpoint(
            lambda: upstream_proto, local_addr=("127.0.0.1", 0)
        )
        upstream_port = upstream_transport.get_extra_info("sockname")[1]

        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            bl = root / "blocklist.txt"
            bl.write_text("doubleclick.net\ncriteo.com\n", encoding="utf-8")
            rules = RuleManager([(bl, "ad")], [root / "wl.txt"])
            stats = StatsStore(root / "stats.json")
            cache = DnsPacketCache()
            cfg = DnsServerConfig(
                enabled=True,
                listen_host="127.0.0.1",
                listen_port=0,
                upstreams=[f"127.0.0.1:{upstream_port}"],
            )
            server = LocalDnsServer(cfg, rules, stats, cache)
            await server.start()
            try:
                # 1. Domínio bloqueado: 0.0.0.0 sem chamar upstream
                r_ad = await _udp_query("127.0.0.1", server.bound_port, make_dns_query("ads.doubleclick.net", txid=0x1111))
                self.assertTrue(r_ad.endswith(b"\x00\x00\x00\x00"))
                self.assertEqual(upstream_proto.queries, [])

                # 2. Canário DoH -> NXDOMAIN
                r_canary = await _udp_query("127.0.0.1", server.bound_port, make_dns_query(DOH_CANARY_DOMAIN, txid=0x1112))
                self.assertEqual(parse_dns_response(r_canary).rcode, 3)

                # 3. Domínio permitido -> vai ao upstream na 1a vez e usa cache na 2a
                r_ok1 = await _udp_query("127.0.0.1", server.bound_port, make_dns_query("example.com", txid=0x2222))
                self.assertEqual(parse_dns_response(r_ok1).txid, 0x2222)
                self.assertEqual(len(upstream_proto.queries), 1)

                r_ok2 = await _udp_query("127.0.0.1", server.bound_port, make_dns_query("example.com", txid=0x3333))
                self.assertEqual(parse_dns_response(r_ok2).txid, 0x3333)
                self.assertEqual(len(upstream_proto.queries), 1)  # Atendido do cache!

                # 4. CNAME cloaking neutralizado antes de voltar ao cliente
                r_cname = await _udp_query("127.0.0.1", server.bound_port, make_dns_query("cloaked.site.test", txid=0x4444))
                self.assertTrue(r_cname.endswith(b"\x00\x00\x00\x00"))
                self.assertEqual(stats.snapshot()["blocked_by_protocol"]["cname"], 1)
            finally:
                await server.stop()
                upstream_transport.close()


if __name__ == "__main__":
    unittest.main()
