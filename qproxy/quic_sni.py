"""Extrator de SNI para pacotes QUIC Initial (HTTP/3, UDP 443) — RFC 9001 / RFC 9369.

Permite bloquear conexões QUIC/HTTP3 de domínios publicitários diretamente nos
pacotes do Windows sem desabilitar QUIC para sites legítimos como o YouTube.

Cadeia de backend criptográfico (zero dependências obrigatórias):
1. `cryptography` (se instalada — aceleração nativa OpenSSL/Rust);
2. `bcrypt.dll` nativa do Windows (CNG com AES-NI em hardware);
3. Fallback compacto em Python puro (AES-128-ECB + AES-128-GCM), permitindo
   operação e testes determinísticos em qualquer plataforma.
"""
from __future__ import annotations

import ctypes
import hashlib
import hmac
import struct
import sys

from .packet_parser import extract_tls_handshake_sni

QUIC_V1 = 0x00000001
QUIC_V2 = 0x6B3343CF

_INITIAL_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
_INITIAL_SALT_V2 = bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9")


# --- HKDF-SHA256 (RFC 5869 + TLS 1.3 RFC 8446 Section 7.1) ---


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand_label(secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
    full_label = b"tls13 " + label
    hkdf_label = (
        struct.pack("!H", length)
        + bytes([len(full_label)])
        + full_label
        + bytes([len(context)])
        + context
    )
    out = bytearray()
    prev = b""
    counter = 1
    while len(out) < length:
        prev = hmac.new(secret, prev + hkdf_label + bytes([counter]), hashlib.sha256).digest()
        out.extend(prev)
        counter += 1
    return bytes(out[:length])


# --- Pure-Python AES-128 (FIPS 197) + AES-128-GCM (NIST SP 800-38D) ---

_SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)
_XTIME = tuple(((i << 1) ^ 0x1B) & 0xFF if i & 0x80 else (i << 1) for i in range(256))


def _aes128_expand_key(key: bytes) -> list[list[int]]:
    w = list(key)
    for r in range(10):
        t0, t1, t2, t3 = w[-4], w[-3], w[-2], w[-1]
        # RotWord + SubWord + Rcon
        t0, t1, t2, t3 = _SBOX[t1] ^ _RCON[r], _SBOX[t2], _SBOX[t3], _SBOX[t0]
        base = len(w) - 16
        w.extend((w[base] ^ t0, w[base + 1] ^ t1, w[base + 2] ^ t2, w[base + 3] ^ t3))
        for _ in range(3):
            base = len(w) - 16
            w.extend(
                (
                    w[base] ^ w[-4],
                    w[base + 1] ^ w[-3],
                    w[base + 2] ^ w[-2],
                    w[base + 3] ^ w[-1],
                )
            )
    return [w[i : i + 16] for i in range(0, 176, 16)]


def _aes128_encrypt_block_py(round_keys: list[list[int]], block: bytes) -> bytes:
    rk0 = round_keys[0]
    s = [block[i] ^ rk0[i] for i in range(16)]
    sbox = _SBOX
    xt = _XTIME

    for r in range(1, 10):
        # SubBytes + ShiftRows
        s = [
            sbox[s[0]], sbox[s[5]], sbox[s[10]], sbox[s[15]],
            sbox[s[4]], sbox[s[9]], sbox[s[14]], sbox[s[3]],
            sbox[s[8]], sbox[s[13]], sbox[s[2]], sbox[s[7]],
            sbox[s[12]], sbox[s[1]], sbox[s[6]], sbox[s[11]],
        ]
        rk = round_keys[r]
        # MixColumns + AddRoundKey
        out = [0] * 16
        for c in (0, 4, 8, 12):
            a0, a1, a2, a3 = s[c], s[c + 1], s[c + 2], s[c + 3]
            t = a0 ^ a1 ^ a2 ^ a3
            out[c] = a0 ^ t ^ xt[a0 ^ a1] ^ rk[c]
            out[c + 1] = a1 ^ t ^ xt[a1 ^ a2] ^ rk[c + 1]
            out[c + 2] = a2 ^ t ^ xt[a2 ^ a3] ^ rk[c + 2]
            out[c + 3] = a3 ^ t ^ xt[a3 ^ a0] ^ rk[c + 3]
        s = out

    rk10 = round_keys[10]
    return bytes(
        (
            sbox[s[0]] ^ rk10[0], sbox[s[5]] ^ rk10[1], sbox[s[10]] ^ rk10[2], sbox[s[15]] ^ rk10[3],
            sbox[s[4]] ^ rk10[4], sbox[s[9]] ^ rk10[5], sbox[s[14]] ^ rk10[6], sbox[s[3]] ^ rk10[7],
            sbox[s[8]] ^ rk10[8], sbox[s[13]] ^ rk10[9], sbox[s[2]] ^ rk10[10], sbox[s[7]] ^ rk10[11],
            sbox[s[12]] ^ rk10[12], sbox[s[1]] ^ rk10[13], sbox[s[6]] ^ rk10[14], sbox[s[11]] ^ rk10[15],
        )
    )


def _gf128_mul(x: int, y: int) -> int:
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ 0xE1000000000000000000000000000000
        else:
            v >>= 1
    return z


def _ghash(h_int: int, aad: bytes, ciphertext: bytes) -> bytes:
    y = 0
    for data in (aad, ciphertext):
        length = len(data)
        full = length & ~15
        for i in range(0, full, 16):
            y = _gf128_mul(y ^ int.from_bytes(data[i : i + 16], "big"), h_int)
        if length != full:
            padded = data[full:] + b"\x00" * (16 - (length - full))
            y = _gf128_mul(y ^ int.from_bytes(padded, "big"), h_int)
    len_block = ((len(aad) * 8) << 64) | (len(ciphertext) * 8)
    y = _gf128_mul(y ^ len_block, h_int)
    return y.to_bytes(16, "big")


def _aes128_ecb_encrypt_py(key: bytes, block: bytes) -> bytes:
    return _aes128_encrypt_block_py(_aes128_expand_key(key), block)


def _aes128_gcm_crypt_py(
    key: bytes,
    nonce: bytes,
    data: bytes,
    aad: bytes,
    encrypt: bool,
    tag: bytes | None = None,
) -> tuple[bytes, bytes] | None:
    rk = _aes128_expand_key(key)
    h_int = int.from_bytes(_aes128_encrypt_block_py(rk, b"\x00" * 16), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    s0 = _aes128_encrypt_block_py(rk, j0)

    if not encrypt:
        if tag is None or len(tag) != 16:
            return None
        gh = _ghash(h_int, aad, data)
        expected_tag = bytes(a ^ b for a, b in zip(gh, s0))
        if not hmac.compare_digest(expected_tag, tag):
            return None

    out = bytearray(len(data))
    ctr = 2
    for offset in range(0, len(data), 16):
        cb = nonce + struct.pack("!I", ctr)
        ctr += 1
        ks = _aes128_encrypt_block_py(rk, cb)
        chunk = data[offset : offset + 16]
        for idx, b in enumerate(chunk):
            out[offset + idx] = b ^ ks[idx]

    result = bytes(out)
    if encrypt:
        gh = _ghash(h_int, aad, result)
        computed_tag = bytes(a ^ b for a, b in zip(gh, s0))
        return result, computed_tag
    return result, tag or b""


# --- Optional accelerated backends (`cryptography` -> Windows `bcrypt.dll` -> pure Python) ---

_CRYPTO_BACKEND = "python"

try:
    from cryptography.hazmat.primitives.ciphers import Cipher as _Cipher
    from cryptography.hazmat.primitives.ciphers import algorithms as _algorithms
    from cryptography.hazmat.primitives.ciphers import modes as _modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM

    _CRYPTO_BACKEND = "cryptography"
except Exception:
    _Cipher = None
    _algorithms = None
    _modes = None
    _AESGCM = None


class _WinBCryptBackend:
    """Backend nativo AES-128-ECB / AES-128-GCM via Windows CNG (`bcrypt.dll`)."""

    class _AuthCipherModeInfo(ctypes.Structure):
        _fields_ = [
            ("cbSize", ctypes.c_uint32),
            ("dwInfoVersion", ctypes.c_uint32),
            ("pbNonce", ctypes.c_void_p),
            ("cbNonce", ctypes.c_uint32),
            ("pbAuthData", ctypes.c_void_p),
            ("cbAuthData", ctypes.c_uint32),
            ("pbTag", ctypes.c_void_p),
            ("cbTag", ctypes.c_uint32),
            ("pbMacContext", ctypes.c_void_p),
            ("cbMacContext", ctypes.c_uint32),
            ("cbAAD", ctypes.c_uint32),
            ("cbData", ctypes.c_uint64),
            ("dwFlags", ctypes.c_uint32),
        ]

    def __init__(self) -> None:
        dll = ctypes.WinDLL("bcrypt")
        dll.BCryptOpenAlgorithmProvider.argtypes = [
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
        ]
        dll.BCryptOpenAlgorithmProvider.restype = ctypes.c_int32

        dll.BCryptSetProperty.argtypes = [
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
        ]
        dll.BCryptSetProperty.restype = ctypes.c_int32

        dll.BCryptCloseAlgorithmProvider.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        dll.BCryptCloseAlgorithmProvider.restype = ctypes.c_int32

        dll.BCryptGenerateSymmetricKey.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
        ]
        dll.BCryptGenerateSymmetricKey.restype = ctypes.c_int32

        dll.BCryptDestroyKey.argtypes = [ctypes.c_void_p]
        dll.BCryptDestroyKey.restype = ctypes.c_int32

        dll.BCryptEncrypt.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_uint32,
        ]
        dll.BCryptEncrypt.restype = ctypes.c_int32

        dll.BCryptDecrypt.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_uint32,
        ]
        dll.BCryptDecrypt.restype = ctypes.c_int32

        self._dll = dll
        self._ecb_alg = ctypes.c_void_p()
        self._gcm_alg = ctypes.c_void_p()

        for attr, mode in (("_ecb_alg", "ChainingModeECB"), ("_gcm_alg", "ChainingModeGCM")):
            alg = ctypes.c_void_p()
            if dll.BCryptOpenAlgorithmProvider(ctypes.byref(alg), "AES", None, 0) != 0:
                raise OSError("BCryptOpenAlgorithmProvider falhou")
            mode_buf = ctypes.create_unicode_buffer(mode)
            if (
                dll.BCryptSetProperty(
                    alg,
                    "ChainingMode",
                    mode_buf,
                    ctypes.sizeof(mode_buf),
                    0,
                )
                != 0
            ):
                dll.BCryptCloseAlgorithmProvider(alg, 0)
                raise OSError(f"BCryptSetProperty({mode}) falhou")
            setattr(self, attr, alg)

        # Auto-verificação FIPS-197 rápida antes de ativar o backend nativo
        test_ct = self.ecb_encrypt(
            bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
            bytes.fromhex("00112233445566778899aabbccddeeff"),
        )
        if test_ct != bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"):
            raise OSError("Auto-teste AES-128-ECB do bcrypt falhou")

    def ecb_encrypt(self, key: bytes, block: bytes) -> bytes:
        hkey = ctypes.c_void_p()
        kbuf = ctypes.create_string_buffer(key, len(key))
        status = self._dll.BCryptGenerateSymmetricKey(
            self._ecb_alg, ctypes.byref(hkey), None, 0, kbuf, len(key), 0
        )
        if status != 0:
            raise OSError(f"BCryptGenerateSymmetricKey falhou: {status}")
        try:
            in_buf = ctypes.create_string_buffer(block, len(block))
            out_buf = ctypes.create_string_buffer(len(block))
            out_len = ctypes.c_uint32(0)
            status = self._dll.BCryptEncrypt(
                hkey, in_buf, len(block), None, None, 0, out_buf, len(block), ctypes.byref(out_len), 0
            )
            if status != 0:
                raise OSError(f"BCryptEncrypt ECB falhou: {status}")
            return out_buf.raw[: out_len.value]
        finally:
            self._dll.BCryptDestroyKey(hkey)

    def gcm_decrypt(
        self, key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes
    ) -> bytes | None:
        hkey = ctypes.c_void_p()
        kbuf = ctypes.create_string_buffer(key, len(key))
        status = self._dll.BCryptGenerateSymmetricKey(
            self._gcm_alg, ctypes.byref(hkey), None, 0, kbuf, len(key), 0
        )
        if status != 0:
            return None
        try:
            nonce_buf = ctypes.create_string_buffer(nonce, len(nonce))
            aad_buf = ctypes.create_string_buffer(aad, len(aad)) if aad else None
            tag_buf = ctypes.create_string_buffer(tag, len(tag))
            info = self._AuthCipherModeInfo()
            info.cbSize = ctypes.sizeof(info)
            info.dwInfoVersion = 1
            info.pbNonce = ctypes.addressof(nonce_buf)
            info.cbNonce = len(nonce)
            if aad_buf is not None:
                info.pbAuthData = ctypes.addressof(aad_buf)
                info.cbAuthData = len(aad)
            info.pbTag = ctypes.addressof(tag_buf)
            info.cbTag = len(tag)

            in_buf = ctypes.create_string_buffer(ciphertext, len(ciphertext))
            out_buf = ctypes.create_string_buffer(len(ciphertext))
            out_len = ctypes.c_uint32(0)
            status = self._dll.BCryptDecrypt(
                hkey,
                in_buf,
                len(ciphertext),
                ctypes.byref(info),
                None,
                0,
                out_buf,
                len(ciphertext),
                ctypes.byref(out_len),
                0,
            )
            if status != 0:
                return None
            return out_buf.raw[: out_len.value]
        finally:
            self._dll.BCryptDestroyKey(hkey)


_WIN_BCRYPT: _WinBCryptBackend | None = None
if _CRYPTO_BACKEND == "python" and sys.platform == "win32":
    try:
        _WIN_BCRYPT = _WinBCryptBackend()
        _CRYPTO_BACKEND = "win_bcrypt"
    except Exception:
        _WIN_BCRYPT = None


def aes128_ecb_encrypt(key: bytes, block: bytes) -> bytes:
    if _CRYPTO_BACKEND == "cryptography" and _Cipher is not None:
        enc = _Cipher(_algorithms.AES(key), _modes.ECB()).encryptor()
        return enc.update(block) + enc.finalize()
    if _WIN_BCRYPT is not None:
        try:
            return _WIN_BCRYPT.ecb_encrypt(key, block)
        except Exception:
            pass
    return _aes128_ecb_encrypt_py(key, block)


def aes128_gcm_decrypt(
    key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes
) -> bytes | None:
    if _CRYPTO_BACKEND == "cryptography" and _AESGCM is not None:
        try:
            return _AESGCM(key).decrypt(nonce, ciphertext + tag, aad)
        except Exception:
            return None
    if _WIN_BCRYPT is not None:
        result = _WIN_BCRYPT.gcm_decrypt(key, nonce, ciphertext, tag, aad)
        if result is not None:
            return result
    decrypted = _aes128_gcm_crypt_py(key, nonce, ciphertext, aad, encrypt=False, tag=tag)
    return decrypted[0] if decrypted is not None else None


def aes128_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Criptografia AES-128-GCM (usada para geração de pacotes QUIC em testes)."""
    if _CRYPTO_BACKEND == "cryptography" and _AESGCM is not None:
        combined = _AESGCM(key).encrypt(nonce, plaintext, aad)
        return combined[:-16], combined[-16:]
    result = _aes128_gcm_crypt_py(key, nonce, plaintext, aad, encrypt=True)
    assert result is not None
    return result


# --- QUIC Varint & Frame Parsing (RFC 9000) ---


def _read_varint(buf: bytes, offset: int) -> tuple[int | None, int]:
    if offset >= len(buf):
        return None, offset
    first = buf[offset]
    prefix = first >> 6
    length = 1 << prefix
    if offset + length > len(buf):
        return None, offset
    value = first & 0x3F
    for idx in range(1, length):
        value = (value << 8) | buf[offset + idx]
    return value, offset + length


def _encode_varint(value: int) -> bytes:
    if value < 0x40:
        return bytes([value])
    if value < 0x4000:
        return struct.pack("!H", 0x4000 | value)
    if value < 0x40000000:
        return struct.pack("!I", 0x80000000 | value)
    return struct.pack("!Q", 0xC000000000000000 | value)


def _derive_initial_keys(dcid: bytes, version: int) -> tuple[bytes, bytes, bytes] | None:
    if version == QUIC_V1:
        salt = _INITIAL_SALT_V1
        key_label, iv_label, hp_label = b"quic key", b"quic iv", b"quic hp"
    elif version == QUIC_V2:
        salt = _INITIAL_SALT_V2
        key_label, iv_label, hp_label = b"quicv2 key", b"quicv2 iv", b"quicv2 hp"
    else:
        return None
    initial_secret = _hkdf_extract(salt, dcid)
    client_secret = _hkdf_expand_label(initial_secret, b"client in", b"", 32)
    key = _hkdf_expand_label(client_secret, key_label, b"", 16)
    iv = _hkdf_expand_label(client_secret, iv_label, b"", 12)
    hp = _hkdf_expand_label(client_secret, hp_label, b"", 16)
    return key, iv, hp


def _extract_crypto_stream(plaintext: bytes) -> bytes:
    """Reconstroi o stream CRYPTO contíguo a partir do offset 0 de um payload QUIC Initial."""
    pos = 0
    length = len(plaintext)
    fragments: dict[int, bytes] = {}

    while pos < length:
        frame_type = plaintext[pos]
        pos += 1
        if frame_type == 0x00 or frame_type == 0x01:  # PADDING / PING
            continue
        if frame_type == 0x06:  # CRYPTO
            offset, pos = _read_varint(plaintext, pos)
            data_len, pos = _read_varint(plaintext, pos)
            if offset is None or data_len is None or pos + data_len > length:
                break
            fragments[offset] = plaintext[pos : pos + data_len]
            pos += data_len
            continue
        # Outros frames (ACK, CONNECTION_CLOSE etc.) — encerra varredura com segurança
        break

    if not fragments:
        return b""

    assembled = bytearray()
    cursor = 0
    for off in sorted(fragments):
        chunk = fragments[off]
        if off > cursor:
            break
        end = off + len(chunk)
        if end > cursor:
            assembled.extend(chunk[cursor - off :])
            cursor = end
    return bytes(assembled)


def extract_quic_initial_sni(udp_payload: bytes) -> str | None:
    """Descriptografa um pacote QUIC Initial (v1 ou v2) e extrai o SNI do ClientHello."""
    if len(udp_payload) < 64:
        return None

    first_byte = udp_payload[0]
    # Long Header (0x80) + Fixed Bit (0x40)
    if (first_byte & 0xC0) != 0xC0:
        return None

    version = struct.unpack_from("!I", udp_payload, 1)[0]
    pkt_type = (first_byte & 0x30) >> 4
    if version == QUIC_V1 and pkt_type != 0:
        return None
    if version == QUIC_V2 and pkt_type != 1:
        return None

    pos = 5
    dcid_len = udp_payload[pos]
    pos += 1
    if dcid_len > 20 or pos + dcid_len >= len(udp_payload):
        return None
    dcid = udp_payload[pos : pos + dcid_len]
    pos += dcid_len

    scid_len = udp_payload[pos]
    pos += 1
    if scid_len > 20 or pos + scid_len >= len(udp_payload):
        return None
    pos += scid_len

    token_len, pos = _read_varint(udp_payload, pos)
    if token_len is None or pos + token_len >= len(udp_payload):
        return None
    pos += token_len

    payload_length, pos = _read_varint(udp_payload, pos)
    if payload_length is None or payload_length < 20:
        return None

    pn_offset = pos
    if pn_offset + payload_length > len(udp_payload):
        return None
    sample_offset = pn_offset + 4
    if sample_offset + 16 > len(udp_payload):
        return None

    keys = _derive_initial_keys(dcid, version)
    if keys is None:
        return None
    key, iv, hp = keys

    sample = udp_payload[sample_offset : sample_offset + 16]
    mask = aes128_ecb_encrypt(hp, sample)
    unmasked_first = first_byte ^ (mask[0] & 0x0F)
    pn_len = (unmasked_first & 0x03) + 1
    if pn_len > 4 or pn_offset + pn_len + 16 > pn_offset + payload_length:
        return None

    unmasked_pn = bytes(udp_payload[pn_offset + i] ^ mask[1 + i] for i in range(pn_len))
    pn_int = int.from_bytes(unmasked_pn, "big")
    pn_12 = pn_int.to_bytes(12, "big")
    nonce = bytes(a ^ b for a, b in zip(iv, pn_12))

    aad = bytes([unmasked_first]) + udp_payload[1:pn_offset] + unmasked_pn
    enc_payload = udp_payload[pn_offset + pn_len : pn_offset + payload_length]
    ciphertext, tag = enc_payload[:-16], enc_payload[-16:]

    plaintext = aes128_gcm_decrypt(key, nonce, ciphertext, tag, aad)
    if plaintext is None:
        return None

    crypto = _extract_crypto_stream(plaintext)
    if not crypto:
        return None
    return extract_tls_handshake_sni(crypto)


def build_quic_initial_packet(
    tls_client_hello_handshake: bytes,
    dcid: bytes = b"\x83\x94\xc8\xf0\x3e\x51\x57\x08",
    scid: bytes = b"",
    version: int = QUIC_V1,
    packet_number: int = 1,
    min_size: int = 1200,
) -> bytes:
    """Gera um pacote QUIC Initial RFC 9000/9369 válido (usado na suíte de testes)."""
    keys = _derive_initial_keys(dcid, version)
    if keys is None:
        raise ValueError(f"Versão QUIC não suportada: {version:#x}")
    key, iv, hp = keys

    pn_bytes = struct.pack("!H", packet_number)
    pn_len = len(pn_bytes)  # 2 bytes
    long_type = 0 if version == QUIC_V1 else 1
    first_byte = 0xC0 | (long_type << 4) | (pn_len - 1)

    crypto_frame = b"\x06\x00" + _encode_varint(len(tls_client_hello_handshake)) + tls_client_hello_handshake
    header_prefix = (
        bytes([first_byte])
        + struct.pack("!I", version)
        + bytes([len(dcid)])
        + dcid
        + bytes([len(scid)])
        + scid
        + b"\x00"  # token_len = 0
    )
    # Calcula padding para atingir min_size (RFC 9000 >= 1200 bytes)
    est_payload_len = pn_len + len(crypto_frame) + 16
    pad_needed = max(0, min_size - (len(header_prefix) + 2 + est_payload_len))
    plaintext = crypto_frame + (b"\x00" * pad_needed)
    total_len_field = pn_len + len(plaintext) + 16
    length_varint = _encode_varint(total_len_field)

    aad = header_prefix + length_varint + pn_bytes
    pn_12 = packet_number.to_bytes(12, "big")
    nonce = bytes(a ^ b for a, b in zip(iv, pn_12))
    ciphertext, tag = aes128_gcm_encrypt(key, nonce, plaintext, aad)

    protected_payload = pn_bytes + ciphertext + tag
    sample = protected_payload[4:20]
    mask = aes128_ecb_encrypt(hp, sample)
    masked_first = first_byte ^ (mask[0] & 0x0F)
    masked_pn = bytes(pn_bytes[i] ^ mask[1 + i] for i in range(pn_len))

    return bytes([masked_first]) + header_prefix[1:] + length_varint + masked_pn + ciphertext + tag
