import socket
import struct
import unittest

from qproxy.packet_parser import (
    DNS_TYPE_A,
    DNS_TYPE_AAAA,
    DNS_TYPE_CNAME,
    DNS_TYPE_HTTPS,
    DNS_TYPE_OPT,
    IPPROTO_TCP,
    IPPROTO_UDP,
    TCP_ACK,
    TCP_FIN,
    TCP_PSH,
    TCP_RST,
    build_dns_blocked_payload,
    build_http_blocked_packet,
    build_tcp_rst_packet,
    build_udp_packet_same_direction,
    build_udp_reply_packet,
    extract_http_request,
    extract_tls_sni,
    internet_checksum,
    parse_dns_query,
    parse_dns_response,
    parse_ip_packet,
    rewrite_dns_cached_payload,
)


def encode_dns_name(domain: str) -> bytes:
    out = bytearray()
    for label in domain.strip(".").split("."):
        b = label.encode("ascii")
        out.append(len(b))
        out.extend(b)
    out.append(0)
    return bytes(out)


def make_dns_query(domain: str, qtype: int = DNS_TYPE_A, txid: int = 0x1234, edns: bool = False) -> bytes:
    arcount = 1 if edns else 0
    hdr = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, arcount)
    question = encode_dns_name(domain) + struct.pack("!HH", qtype, 1)
    opt = b"\x00" + struct.pack("!HHIH", DNS_TYPE_OPT, 4096, 0x00008000, 0) if edns else b""
    return hdr + question + opt


def make_dns_a_response(
    domain: str, ip: str = "93.184.216.34", ttl: int = 300, txid: int = 0x1234, edns: bool = False
) -> bytes:
    arcount = 1 if edns else 0
    hdr = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, arcount)
    question = encode_dns_name(domain) + struct.pack("!HH", DNS_TYPE_A, 1)
    answer = struct.pack("!HHHIH4s", 0xC00C, DNS_TYPE_A, 1, ttl, 4, socket.inet_aton(ip))
    opt = b"\x00" + struct.pack("!HHIH", DNS_TYPE_OPT, 4096, 0x00008000, 0) if edns else b""
    return hdr + question + answer + opt


def make_dns_cname_response(domain: str, cname_target: str, ip: str = "1.2.3.4", txid: int = 0x4321) -> bytes:
    hdr = struct.pack("!HHHHHH", txid, 0x8180, 1, 2, 0, 0)
    question = encode_dns_name(domain) + struct.pack("!HH", DNS_TYPE_A, 1)
    cname_rdata = encode_dns_name(cname_target)
    rr1 = struct.pack("!HHHIH", 0xC00C, DNS_TYPE_CNAME, 1, 120, len(cname_rdata)) + cname_rdata
    rr2 = encode_dns_name(cname_target) + struct.pack("!HHIH4s", DNS_TYPE_A, 1, 120, 4, socket.inet_aton(ip))
    return hdr + question + rr1 + rr2


def make_ipv4_udp(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    udp_len = 8 + len(payload)
    udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
    ip_hdr = bytearray(
        struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, 20 + udp_len, 0x1111, 0x4000, 64, IPPROTO_UDP, 0,
            socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
        )
    )
    struct.pack_into("!H", ip_hdr, 10, internet_checksum(ip_hdr))
    return bytes(ip_hdr) + udp_hdr + payload


def make_ipv6_tcp(
    src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes, seq: int = 100, ack: int = 200
) -> bytes:
    tcp_hdr = struct.pack("!HHIIHHHH", src_port, dst_port, seq, ack, (5 << 12) | TCP_PSH | TCP_ACK, 65535, 0, 0)
    l4 = tcp_hdr + payload
    ip6_hdr = struct.pack(
        "!IHBB16s16s",
        0x60000000, len(l4), IPPROTO_TCP, 64,
        socket.inet_pton(socket.AF_INET6, src_ip),
        socket.inet_pton(socket.AF_INET6, dst_ip),
    )
    return ip6_hdr + l4


def make_ipv4_tcp(
    src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes, seq: int = 1000, ack: int = 5000
) -> bytes:
    tcp_hdr = struct.pack("!HHIIHHHH", src_port, dst_port, seq, ack, (5 << 12) | TCP_PSH | TCP_ACK, 65535, 0, 0)
    l4 = tcp_hdr + payload
    ip_hdr = bytearray(
        struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, 20 + len(l4), 0x2222, 0x4000, 64, IPPROTO_TCP, 0,
            socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
        )
    )
    struct.pack_into("!H", ip_hdr, 10, internet_checksum(ip_hdr))
    return bytes(ip_hdr) + l4


def make_tls_client_hello(hostname: str, extra_trailing_ext_len: int = 0) -> bytes:
    host_b = hostname.encode("ascii")
    sni_entry = b"\x00" + struct.pack("!H", len(host_b)) + host_b
    sni_ext = struct.pack("!HHH", 0x0000, len(sni_entry) + 2, len(sni_entry)) + sni_entry
    # Opcionalmente simula extensão pós-quântica (ML-KEM key_share) truncada no final do segmento
    extra_ext = struct.pack("!HH", 0x0033, extra_trailing_ext_len) + (b"\x42" * min(extra_trailing_ext_len, 20)) if extra_trailing_ext_len else b""
    exts_len = len(sni_ext) + (4 + extra_trailing_ext_len if extra_trailing_ext_len else 0)
    ch_body = b"\x03\x03" + (b"\x11" * 32) + b"\x00\x00\x02\x13\x01\x01\x00" + struct.pack("!H", exts_len) + sni_ext + extra_ext
    handshake = b"\x01" + (len(ch_body) + (extra_trailing_ext_len - min(extra_trailing_ext_len, 20) if extra_trailing_ext_len else 0)).to_bytes(3, "big") + ch_body
    rec_len = min(0xFFFF, len(handshake))
    return b"\x16\x03\x01" + struct.pack("!H", rec_len) + handshake


class PacketParserTests(unittest.TestCase):
    def test_dns_query_and_blocked_replies(self):
        q_a = make_dns_query("ads.doubleclick.net", DNS_TYPE_A, txid=0xABCD, edns=True)
        parsed = parse_dns_query(q_a)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.qname, "ads.doubleclick.net")
        self.assertEqual(parsed.qtype, DNS_TYPE_A)
        self.assertEqual(parsed.txid, 0xABCD)

        # A -> 0.0.0.0
        reply_a = build_dns_blocked_payload(q_a, mode="zero_ip", ttl=60)
        self.assertIsNotNone(reply_a)
        self.assertTrue(reply_a.endswith(b"\x00\x00\x00\x00"))
        resp_a = parse_dns_response(reply_a)
        self.assertEqual(resp_a.rcode, 0)
        self.assertEqual(resp_a.answer_count, 1)

        # AAAA -> ::
        q_aaaa = make_dns_query("ads.doubleclick.net", DNS_TYPE_AAAA, txid=0x1111)
        reply_aaaa = build_dns_blocked_payload(q_aaaa, mode="zero_ip", ttl=60)
        self.assertTrue(reply_aaaa.endswith(b"\x00" * 16))

        # HTTPS (type 65) -> NOERROR NODATA (0 answers)
        q_https = make_dns_query("ads.doubleclick.net", DNS_TYPE_HTTPS, txid=0x2222)
        reply_https = build_dns_blocked_payload(q_https, mode="zero_ip")
        resp_https = parse_dns_response(reply_https)
        self.assertEqual(resp_https.rcode, 0)
        self.assertEqual(resp_https.answer_count, 0)

        # NXDOMAIN mode
        reply_nx = build_dns_blocked_payload(q_a, mode="nxdomain")
        resp_nx = parse_dns_response(reply_nx)
        self.assertEqual(resp_nx.rcode, 3)

    def test_dns_compression_loop_protection(self):
        # Ponteiro apontando para si mesmo no offset 12 (0xC0 0x0C)
        malicious = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c\x00\x01\x00\x01"
        self.assertIsNone(parse_dns_query(malicious))

    def test_dns_cname_response_and_cache_rewrite_preserves_edns_opt(self):
        resp_bytes = make_dns_cname_response("metrics.site.test", "tracker.criteo.com")
        parsed = parse_dns_response(resp_bytes)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.qname, "metrics.site.test")
        self.assertEqual(parsed.cnames, ("tracker.criteo.com",))
        self.assertEqual(parsed.min_ttl, 120)

        # Reescreve TXID e TTL preservando flags EDNS0 OPT (0x00008000)
        cached = make_dns_a_response("example.com", ttl=300, txid=0x0001, edns=True)
        rewritten = rewrite_dns_cached_payload(cached, new_txid=0x9999, remaining_ttl=45)
        self.assertEqual(struct.unpack_from("!H", rewritten, 0)[0], 0x9999)
        reparsed = parse_dns_response(rewritten)
        self.assertEqual(reparsed.min_ttl, 45)
        # Últimos 11 bytes = OPT RR com flags 0x00008000 intactas
        self.assertEqual(rewritten[-11:], cached[-11:])

    def test_tls_sni_extraction_including_truncated_post_quantum_segment(self):
        ch_normal = make_tls_client_hello("googleads.g.doubleclick.net")
        self.assertEqual(extract_tls_sni(ch_normal), "googleads.g.doubleclick.net")

        ch_pq_truncated = make_tls_client_hello("ads.tiktok.com", extra_trailing_ext_len=1216)
        self.assertEqual(extract_tls_sni(ch_pq_truncated), "ads.tiktok.com")

        # Pacote não-ClientHello (Application Data 0x17) retorna None
        self.assertIsNone(extract_tls_sni(b"\x17\x03\x03" + b"\x00" * 60))

    def test_http_request_extraction(self):
        raw = b"GET /pagead/js/adsbygoogle.js HTTP/1.1\r\nHost: pagead2.googlesyndication.com:80\r\nUser-Agent: Test\r\n\r\n"
        info = extract_http_request(raw)
        self.assertIsNotNone(info)
        self.assertEqual(info.method, "GET")
        self.assertEqual(info.host, "pagead2.googlesyndication.com")
        self.assertEqual(info.path, "/pagead/js/adsbygoogle.js")

    def test_forged_udp_tcp_rst_and_http_packets_have_valid_checksums(self):
        dns_q = make_dns_query("ads.test", DNS_TYPE_A)
        orig_udp = parse_ip_packet(make_ipv4_udp("192.168.1.10", "8.8.8.8", 55000, 53, dns_q))
        self.assertIsNotNone(orig_udp)
        reply_payload = build_dns_blocked_payload(dns_q)
        reply_raw = build_udp_reply_packet(orig_udp, reply_payload)

        # Verifica IPv4 header checksum == 0 (RFC 1071)
        self.assertEqual(internet_checksum(reply_raw[:20]), 0)
        reparsed = parse_ip_packet(reply_raw)
        self.assertEqual(reparsed.src_ip_str, "8.8.8.8")
        self.assertEqual(reparsed.dst_ip_str, "192.168.1.10")
        self.assertEqual(reparsed.src_port, 53)
        self.assertEqual(reparsed.dst_port, 55000)

        same_dir = parse_ip_packet(build_udp_packet_same_direction(orig_udp, reply_payload))
        self.assertEqual(same_dir.src_ip_str, "192.168.1.10")
        self.assertEqual(same_dir.dst_ip_str, "8.8.8.8")

        # IPv4 TCP RST + HTTP 204
        orig_tcp = parse_ip_packet(make_ipv4_tcp("192.168.1.10", "1.2.3.4", 54321, 443, b"hello", seq=100, ack=500))
        rst_raw = build_tcp_rst_packet(orig_tcp, to_client=True)
        self.assertEqual(internet_checksum(rst_raw[:20]), 0)
        rst = parse_ip_packet(rst_raw)
        self.assertEqual(rst.tcp_flags, TCP_RST | TCP_ACK)
        self.assertEqual(rst.tcp_seq, 500)
        self.assertEqual(rst.tcp_ack, 105)

        http_raw = build_http_blocked_packet(orig_tcp)
        self.assertEqual(internet_checksum(http_raw[:20]), 0)
        http_pkt = parse_ip_packet(http_raw)
        self.assertEqual(http_pkt.tcp_flags, TCP_PSH | TCP_ACK | TCP_FIN)
        self.assertIn(b"204 No Content", http_pkt.payload)

        # IPv6 TCP RST
        orig_v6 = parse_ip_packet(make_ipv6_tcp("2001:db8::1", "2001:db8::2", 60000, 443, b"clienthello", seq=10, ack=20))
        rst_v6 = parse_ip_packet(build_tcp_rst_packet(orig_v6, to_client=True))
        self.assertEqual(rst_v6.ip_version, 6)
        self.assertEqual(rst_v6.src_ip_str, "2001:db8::2")
        self.assertEqual(rst_v6.dst_ip_str, "2001:db8::1")
        self.assertEqual(rst_v6.tcp_flags, TCP_RST | TCP_ACK)


if __name__ == "__main__":
    unittest.main()
