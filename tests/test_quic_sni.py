import struct
import unittest

from qproxy.quic_sni import (
    QUIC_V1,
    QUIC_V2,
    _aes128_ecb_encrypt_py,
    _aes128_gcm_crypt_py,
    _derive_initial_keys,
    build_quic_initial_packet,
    extract_quic_initial_sni,
)


def _make_tls_handshake_client_hello(hostname: str) -> bytes:
    host_b = hostname.encode("ascii")
    sni_entry = b"\x00" + struct.pack("!H", len(host_b)) + host_b
    sni_ext = struct.pack("!HHH", 0x0000, len(sni_entry) + 2, len(sni_entry)) + sni_entry
    body = b"\x03\x03" + (b"\x22" * 32) + b"\x00\x00\x02\x13\x01\x01\x00" + struct.pack("!H", len(sni_ext)) + sni_ext
    return b"\x01" + len(body).to_bytes(3, "big") + body


class QuicSniTests(unittest.TestCase):
    def test_fips197_aes128_vector(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        self.assertEqual(
            _aes128_ecb_encrypt_py(key, pt).hex(),
            "69c4e0d86a7b0430d8cdb78070b4c55a",
        )

    def test_pure_python_aes128_gcm_roundtrip_and_tamper_detection(self):
        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
        nonce = bytes.fromhex("cafebabefacedbaddecaf888")
        aad = b"quic-header-aad"
        pt = b"hello qproxy quic initial payload!"
        ct, tag = _aes128_gcm_crypt_py(key, nonce, pt, aad, encrypt=True)
        dec = _aes128_gcm_crypt_py(key, nonce, ct, aad, encrypt=False, tag=tag)
        self.assertIsNotNone(dec)
        self.assertEqual(dec[0], pt)

        bad_tag = bytes([tag[0] ^ 0xFF]) + tag[1:]
        self.assertIsNone(_aes128_gcm_crypt_py(key, nonce, ct, aad, encrypt=False, tag=bad_tag))

    def test_rfc9001_appendix_a1_initial_key_derivation(self):
        dcid = bytes.fromhex("8394c8f03e515708")
        key, iv, hp = _derive_initial_keys(dcid, QUIC_V1)
        self.assertEqual(key.hex(), "1f369613dd76d5467730efcbe3b1a22d")
        self.assertEqual(iv.hex(), "fa044b2f42a3fd3b46fb255c")
        self.assertEqual(hp.hex(), "9f50449e04a0e810283a1e9933adedd2")

    def test_quic_v1_and_v2_initial_sni_extraction(self):
        ch = _make_tls_handshake_client_hello("googleads.g.doubleclick.net")
        pkt_v1 = build_quic_initial_packet(ch, version=QUIC_V1)
        self.assertGreaterEqual(len(pkt_v1), 1200)
        self.assertEqual(extract_quic_initial_sni(pkt_v1), "googleads.g.doubleclick.net")

        pkt_v2 = build_quic_initial_packet(ch, version=QUIC_V2, packet_number=7)
        self.assertEqual(extract_quic_initial_sni(pkt_v2), "googleads.g.doubleclick.net")

    def test_invalid_or_short_header_quic_returns_none(self):
        # 1-RTT short header (bit 7 == 0)
        self.assertIsNone(extract_quic_initial_sni(b"\x40" + b"\x00" * 1200))
        self.assertIsNone(extract_quic_initial_sni(b"\xc0\x00\x00\x00\x01" + b"\x00" * 10))


if __name__ == "__main__":
    unittest.main()
