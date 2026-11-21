"""Parser e sintetizador de pacotes IPv4/IPv6, TCP/UDP, DNS, TLS SNI e HTTP.

Implementação 100% Python padrão (sem dependências externas), projetada para
inspeção de pacotes em nível de rede no Windows (WinDivert) e para testes
determinísticos em qualquer sistema operacional.
"""
from __future__ import annotations

from dataclasses import dataclass
import socket
import struct


IPPROTO_TCP = 6
IPPROTO_UDP = 17

DNS_TYPE_A = 1
DNS_TYPE_CNAME = 5
DNS_TYPE_AAAA = 28
DNS_TYPE_OPT = 41
DNS_TYPE_SVCB = 64
DNS_TYPE_HTTPS = 65

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10

HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ")
_IPV6_EXT_HEADERS = frozenset({0, 43, 44, 50, 51, 60})


@dataclass(frozen=True, slots=True)
class ParsedPacket:
    ip_version: int  # 4 or 6
    protocol: int  # IPPROTO_TCP or IPPROTO_UDP
    src_ip: bytes  # 4 bytes (IPv4) or 16 bytes (IPv6)
    dst_ip: bytes
    src_port: int
    dst_port: int
    ip_header_len: int
    transport_header_len: int
    payload: bytes
    raw: bytes
    # Campos TCP (0 para UDP)
    tcp_seq: int = 0
    tcp_ack: int = 0
    tcp_flags: int = 0

    @property
    def is_ipv6(self) -> bool:
        return self.ip_version == 6

    @property
    def src_ip_str(self) -> str:
        family = socket.AF_INET6 if self.ip_version == 6 else socket.AF_INET
        return socket.inet_ntop(family, self.src_ip)

    @property
    def dst_ip_str(self) -> str:
        family = socket.AF_INET6 if self.ip_version == 6 else socket.AF_INET
        return socket.inet_ntop(family, self.dst_ip)


@dataclass(frozen=True, slots=True)
class DnsQuery:
    txid: int
    flags: int
    qname: str
    qtype: int
    qclass: int
    question_end: int


@dataclass(frozen=True, slots=True)
class DnsResponse:
    txid: int
    flags: int
    rcode: int
    qname: str
    qtype: int
    cnames: tuple[str, ...]
    min_ttl: int
    answer_count: int


@dataclass(frozen=True, slots=True)
class HttpRequestInfo:
    method: str
    path: str
    host: str


def internet_checksum(data: bytes | bytearray | memoryview) -> int:
    """Calcula checksum RFC 1071 (complemento de 1 em palavras de 16 bits)."""
    view = memoryview(data)
    length = len(view)
    total = 0
    if length >= 2:
        even_len = length & ~1
        for i in range(0, even_len, 2):
            total += (view[i] << 8) | view[i + 1]
    if length & 1:
        total += view[-1] << 8
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _transport_checksum(
    ip_version: int,
    src_ip: bytes,
    dst_ip: bytes,
    protocol: int,
    segment: bytes,
) -> int:
    if ip_version == 4:
        pseudo = struct.pack("!4s4sBBH", src_ip, dst_ip, 0, protocol, len(segment))
    else:
        pseudo = struct.pack("!16s16sI3xB", src_ip, dst_ip, len(segment), protocol)
    checksum = internet_checksum(pseudo + segment)
    if protocol == IPPROTO_UDP and checksum == 0:
        return 0xFFFF
    return checksum


def parse_ip_packet(raw: bytes | bytearray | memoryview) -> ParsedPacket | None:
    """Disseca pacotes IPv4/IPv6 + TCP/UDP retornando metadados e payload."""
    data = bytes(raw)
    if len(data) < 20:
        return None

    version = data[0] >> 4
    if version == 4:
        ihl = (data[0] & 0x0F) * 4
        if ihl < 20 or len(data) < ihl:
            return None
        total_len = struct.unpack_from("!H", data, 2)[0]
        if total_len < ihl:
            return None
        packet_end = min(len(data), total_len)
        frag_field = struct.unpack_from("!H", data, 6)[0]
        # Ignora fragmentos não iniciais (offset != 0)
        if (frag_field & 0x1FFF) != 0:
            return None
        protocol = data[9]
        src_ip = data[12:16]
        dst_ip = data[16:20]
        l4_offset = ihl
    elif version == 6:
        if len(data) < 40:
            return None
        payload_len = struct.unpack_from("!H", data, 4)[0]
        next_hdr = data[6]
        src_ip = data[8:24]
        dst_ip = data[24:40]
        l4_offset = 40
        packet_end = min(len(data), 40 + payload_len)
        # Avança eventuais extension headers de IPv6
        hops = 0
        while next_hdr in _IPV6_EXT_HEADERS and hops < 8:
            hops += 1
            if next_hdr == 44:  # Fragment header (8 bytes fixos)
                if l4_offset + 8 > packet_end:
                    return None
                frag_off = struct.unpack_from("!H", data, l4_offset + 2)[0] >> 3
                if frag_off != 0:
                    return None
                next_hdr = data[l4_offset]
                l4_offset += 8
            else:
                if l4_offset + 2 > packet_end:
                    return None
                ext_len = (data[l4_offset + 1] + 1) * 8
                if l4_offset + ext_len > packet_end:
                    return None
                next_hdr = data[l4_offset]
                l4_offset += ext_len
        protocol = next_hdr
    else:
        return None

    if protocol == IPPROTO_UDP:
        if l4_offset + 8 > packet_end:
            return None
        src_port, dst_port, udp_len, _ = struct.unpack_from("!HHHH", data, l4_offset)
        if udp_len < 8:
            return None
        payload_end = min(packet_end, l4_offset + udp_len)
        payload = data[l4_offset + 8 : payload_end]
        return ParsedPacket(
            ip_version=version,
            protocol=IPPROTO_UDP,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            ip_header_len=l4_offset,
            transport_header_len=8,
            payload=payload,
            raw=data[:packet_end],
        )

    if protocol == IPPROTO_TCP:
        if l4_offset + 20 > packet_end:
            return None
        src_port, dst_port, seq, ack, off_flags = struct.unpack_from("!HHIIH", data, l4_offset)
        tcp_hdr_len = ((off_flags >> 12) & 0x0F) * 4
        if tcp_hdr_len < 20 or l4_offset + tcp_hdr_len > packet_end:
            return None
        flags = off_flags & 0x3F
        payload = data[l4_offset + tcp_hdr_len : packet_end]
        return ParsedPacket(
            ip_version=version,
            protocol=IPPROTO_TCP,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            ip_header_len=l4_offset,
            transport_header_len=tcp_hdr_len,
            payload=payload,
            raw=data[:packet_end],
            tcp_seq=seq,
            tcp_ack=ack,
            tcp_flags=flags,
        )

    return None


def _decode_dns_name(payload: bytes, offset: int) -> tuple[str | None, int]:
    """Decodifica um nome DNS (suporta ponteiros de compressão RFC 1035 com proteção contra loops)."""
    length = len(payload)
    labels: list[str] = []
    pos = offset
    end_pos: int | None = None
    visited: set[int] = set()
    jumps = 0

    while pos < length:
        if pos in visited or jumps > 32:
            return None, offset
        visited.add(pos)
        byte = payload[pos]
        if byte == 0:
            if end_pos is None:
                end_pos = pos + 1
            break
        if (byte & 0xC0) == 0xC0:
            if pos + 1 >= length:
                return None, offset
            ptr = ((byte & 0x3F) << 8) | payload[pos + 1]
            if ptr >= length:
                return None, offset
            if end_pos is None:
                end_pos = pos + 2
            pos = ptr
            jumps += 1
            continue
        if (byte & 0xC0) != 0:
            return None, offset
        label_len = byte
        pos += 1
        if pos + label_len > length:
            return None, offset
        label_bytes = payload[pos : pos + label_len]
        try:
            labels.append(label_bytes.decode("ascii", errors="strict").lower())
        except UnicodeDecodeError:
            try:
                labels.append(label_bytes.decode("utf-8", errors="ignore").lower())
            except Exception:
                return None, offset
        pos += label_len
    else:
        return None, offset

    if end_pos is None:
        return None, offset
    name = ".".join(label for label in labels if label).rstrip(".")
    return name, end_pos


def parse_dns_query(payload: bytes) -> DnsQuery | None:
    """Extrai consulta DNS padrão (QR == 0, QDCOUNT >= 1)."""
    if len(payload) < 17:
        return None
    txid, flags, qdcount, _, _, _ = struct.unpack_from("!HHHHHH", payload, 0)
    # QR bit == 1 significa resposta, não consulta
    if (flags & 0x8000) != 0 or qdcount < 1:
        return None
    qname, pos = _decode_dns_name(payload, 12)
    if not qname or pos + 4 > len(payload):
        return None
    qtype, qclass = struct.unpack_from("!HH", payload, pos)
    return DnsQuery(
        txid=txid,
        flags=flags,
        qname=qname,
        qtype=qtype,
        qclass=qclass,
        question_end=pos + 4,
    )


def parse_dns_response(payload: bytes) -> DnsResponse | None:
    """Analisa resposta DNS (QR == 1), extraindo CNAMEs e menor TTL para cache e bloqueio de CNAME cloaking."""
    if len(payload) < 12:
        return None
    txid, flags, qdcount, ancount, _, _ = struct.unpack_from("!HHHHHH", payload, 0)
    if (flags & 0x8000) == 0 or qdcount < 1:
        return None
    rcode = flags & 0x000F

    pos = 12
    first_qname = ""
    first_qtype = 0
    for idx in range(qdcount):
        qname, next_pos = _decode_dns_name(payload, pos)
        if qname is None or next_pos + 4 > len(payload):
            return None
        qtype, _ = struct.unpack_from("!HH", payload, next_pos)
        if idx == 0:
            first_qname = qname
            first_qtype = qtype
        pos = next_pos + 4

    cnames: list[str] = []
    min_ttl: int | None = None

    for _ in range(ancount):
        _, next_pos = _decode_dns_name(payload, pos)
        if next_pos + 10 > len(payload):
            break
        rtype, _rclass, ttl, rdlength = struct.unpack_from("!HHIH", payload, next_pos)
        rdata_start = next_pos + 10
        rdata_end = rdata_start + rdlength
        if rdata_end > len(payload):
            break
        if rtype != DNS_TYPE_OPT:
            if min_ttl is None or ttl < min_ttl:
                min_ttl = ttl
        if rtype == DNS_TYPE_CNAME:
            target, _ = _decode_dns_name(payload, rdata_start)
            if target:
                cnames.append(target)
        pos = rdata_end

    return DnsResponse(
        txid=txid,
        flags=flags,
        rcode=rcode,
        qname=first_qname,
        qtype=first_qtype,
        cnames=tuple(cnames),
        min_ttl=min_ttl if min_ttl is not None else 60,
        answer_count=ancount,
    )


def build_dns_blocked_payload(
    query_payload: bytes,
    mode: str = "zero_ip",
    ttl: int = 60,
) -> bytes | None:
    """Constrói resposta DNS instantânea para domínio bloqueado.

    - mode='zero_ip':
        A     -> 0.0.0.0 (TTL 60s)
        AAAA  -> :: (TTL 60s)
        HTTPS/SVCB -> NOERROR sem registros (evita atraso de HTTP/3 no Chrome/Edge)
        Outros -> NXDOMAIN
    - mode='nxdomain':
        Retorna NXDOMAIN (RCODE=3) para qualquer tipo (ideal para canário DoH).
    """
    query = parse_dns_query(query_payload)
    if query is None:
        return None

    question = query_payload[12 : query.question_end]
    rd_bit = query.flags & 0x0100
    # QR=1 (0x8000) | RD (preservado) | RA=1 (0x0080)
    base_flags = 0x8080 | rd_bit
    safe_ttl = max(1, min(int(ttl), 3600))

    if mode == "nxdomain":
        header = struct.pack("!HHHHHH", query.txid, base_flags | 0x0003, 1, 0, 0, 0)
        return header + question

    if query.qtype == DNS_TYPE_A:
        header = struct.pack("!HHHHHH", query.txid, base_flags, 1, 1, 0, 0)
        answer = struct.pack("!HHHIH4s", 0xC00C, DNS_TYPE_A, 1, safe_ttl, 4, b"\x00\x00\x00\x00")
        return header + question + answer

    if query.qtype == DNS_TYPE_AAAA:
        header = struct.pack("!HHHHHH", query.txid, base_flags, 1, 1, 0, 0)
        answer = struct.pack("!HHHIH16s", 0xC00C, DNS_TYPE_AAAA, 1, safe_ttl, 16, b"\x00" * 16)
        return header + question + answer

    if query.qtype in (DNS_TYPE_HTTPS, DNS_TYPE_SVCB):
        header = struct.pack("!HHHHHH", query.txid, base_flags, 1, 0, 0, 0)
        return header + question

    header = struct.pack("!HHHHHH", query.txid, base_flags | 0x0003, 1, 0, 0, 0)
    return header + question


def build_dns_blocked_from_response(
    response_payload: bytes,
    mode: str = "zero_ip",
    ttl: int = 60,
) -> bytes | None:
    """Converte uma resposta DNS (ex.: CNAME cloaking detectado) em resposta bloqueada."""
    if len(response_payload) < 17:
        return None
    txid, flags, qdcount, _, _, _ = struct.unpack_from("!HHHHHH", response_payload, 0)
    if qdcount < 1:
        return None
    qname, pos = _decode_dns_name(response_payload, 12)
    if not qname or pos + 4 > len(response_payload):
        return None
    # Constrói pseudo-consulta sintética mantendo TXID, RD e Question originais
    synth_query = struct.pack("!HHHHHH", txid, flags & 0x0100, 1, 0, 0, 0) + response_payload[12 : pos + 4]
    return build_dns_blocked_payload(synth_query, mode=mode, ttl=ttl)


def rewrite_dns_cached_payload(
    cached_payload: bytes,
    new_txid: int,
    remaining_ttl: int,
) -> bytes:
    """Reescreve TXID e TTLs restantes (sem tocar registros EDNS0 OPT) de uma resposta DNS em cache."""
    if len(cached_payload) < 12:
        return cached_payload
    out = bytearray(cached_payload)
    struct.pack_into("!H", out, 0, new_txid & 0xFFFF)

    _, _, qdcount, ancount, nscount, arcount = struct.unpack_from("!HHHHHH", out, 0)
    pos = 12
    for _ in range(qdcount):
        _, next_pos = _decode_dns_name(cached_payload, pos)
        if next_pos + 4 > len(out):
            return bytes(out)
        pos = next_pos + 4

    safe_ttl = max(1, int(remaining_ttl))
    for _ in range(ancount + nscount + arcount):
        _, next_pos = _decode_dns_name(cached_payload, pos)
        if next_pos + 10 > len(out):
            break
        rtype, _, cur_ttl, rdlength = struct.unpack_from("!HHIH", out, next_pos)
        if rtype != DNS_TYPE_OPT:
            struct.pack_into("!I", out, next_pos + 4, min(cur_ttl, safe_ttl))
        pos = next_pos + 10 + rdlength
        if pos > len(out):
            break

    return bytes(out)


def extract_tls_handshake_sni(handshake: bytes) -> str | None:
    """Extrai o hostname SNI (extensão 0x0000) de uma mensagem TLS ClientHello.

    Tolera pacotes truncados (comuns com troca de chaves pós-quântica ML-KEM
    em Chrome/Edge/Firefox quando o ClientHello é dividido em dois segmentos TCP
    ou em pacotes QUIC Initial).
    """
    length = len(handshake)
    if length < 42 or handshake[0] != 0x01:
        return None

    # Handshake header: 1 byte type (0x01) + 3 bytes length
    # ClientHello: 2 bytes legacy_version + 32 bytes random = offset 38
    pos = 38
    if pos >= length:
        return None

    # Session ID
    session_id_len = handshake[pos]
    pos += 1 + session_id_len
    if pos + 2 > length:
        return None

    # Cipher Suites
    cipher_suites_len = struct.unpack_from("!H", handshake, pos)[0]
    pos += 2 + cipher_suites_len
    if pos + 1 > length:
        return None

    # Compression Methods
    comp_len = handshake[pos]
    pos += 1 + comp_len
    if pos + 2 > length:
        return None

    # Extensions
    ext_total_len = struct.unpack_from("!H", handshake, pos)[0]
    pos += 2
    ext_end = min(length, pos + ext_total_len)

    while pos + 4 <= ext_end:
        ext_type, ext_len = struct.unpack_from("!HH", handshake, pos)
        pos += 4
        if ext_type == 0x0000:  # server_name (SNI)
            if pos + 2 > length:
                return None
            list_len = struct.unpack_from("!H", handshake, pos)[0]
            sni_pos = pos + 2
            sni_end = min(length, sni_pos + list_len)
            while sni_pos + 3 <= sni_end:
                name_type = handshake[sni_pos]
                name_len = struct.unpack_from("!H", handshake, sni_pos + 1)[0]
                sni_pos += 3
                if sni_pos + name_len > sni_end:
                    return None
                if name_type == 0x00 and name_len > 0:
                    try:
                        host = handshake[sni_pos : sni_pos + name_len].decode("ascii").strip().lower().rstrip(".")
                        return host or None
                    except UnicodeDecodeError:
                        return None
                sni_pos += name_len
            return None
        if pos + ext_len > ext_end:
            # Extensão longa (ex.: ML-KEM key_share) truncada no final do segmento
            return None
        pos += ext_len
    return None


def extract_tls_sni(payload: bytes) -> str | None:
    """Extrai o hostname SNI diretamente do payload TCP de um TLS ClientHello."""
    if len(payload) < 47:
        return None
    # ContentType = 0x16 (Handshake), Legacy Version = 0x03 0x00..0x04
    if payload[0] != 0x16 or payload[1] != 0x03 or payload[2] > 0x04:
        return None
    if payload[5] != 0x01:
        return None
    return extract_tls_handshake_sni(payload[5:])


def extract_http_request(payload: bytes) -> HttpRequestInfo | None:
    """Extrai método, caminho e cabeçalho Host de uma requisição HTTP em texto claro."""
    if len(payload) < 16 or not payload.startswith(HTTP_METHODS):
        return None
    header_end = payload.find(b"\r\n\r\n")
    head = payload[: header_end if header_end != -1 else min(len(payload), 4096)]
    try:
        text = head.decode("iso-8859-1")
    except UnicodeDecodeError:
        return None
    lines = text.split("\r\n")
    if not lines:
        return None
    parts = lines[0].split(" ", 2)
    if len(parts) < 2:
        return None
    method = parts[0].upper()
    path = parts[1].strip() or "/"
    host = ""
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        if name.strip().lower() == "host":
            raw_host = value.strip().lower()
            if raw_host.startswith("[") and "]" in raw_host:
                host = raw_host[1 : raw_host.index("]")]
            elif ":" in raw_host and raw_host.count(":") == 1:
                host = raw_host.rsplit(":", 1)[0]
            else:
                host = raw_host
            host = host.rstrip(".")
            break
    if not host:
        return None
    return HttpRequestInfo(method=method, path=path, host=host)


def _build_ip_header(
    ip_version: int,
    src_ip: bytes,
    dst_ip: bytes,
    protocol: int,
    l4_length: int,
    ttl: int = 64,
    ident: int = 0x5150,
) -> bytes:
    if ip_version == 4:
        total_len = 20 + l4_length
        hdr = bytearray(
            struct.pack(
                "!BBHHHBBH4s4s",
                0x45,
                0,
                total_len,
                ident & 0xFFFF,
                0x4000,  # DF
                ttl & 0xFF,
                protocol & 0xFF,
                0,
                src_ip,
                dst_ip,
            )
        )
        csum = internet_checksum(hdr)
        struct.pack_into("!H", hdr, 10, csum)
        return bytes(hdr)
    # IPv6: 40 bytes fixos
    return struct.pack(
        "!IHBB16s16s",
        0x60000000,
        l4_length & 0xFFFF,
        protocol & 0xFF,
        ttl & 0xFF,
        src_ip,
        dst_ip,
    )


def build_udp_reply_packet(original: ParsedPacket, reply_payload: bytes) -> bytes:
    """Constrói pacote IPv4/IPv6 + UDP completo invertendo origem/destino (para injeção inbound)."""
    src_ip = original.dst_ip
    dst_ip = original.src_ip
    src_port = original.dst_port
    dst_port = original.src_port
    udp_len = 8 + len(reply_payload)

    udp_hdr = bytearray(struct.pack("!HHHH", src_port, dst_port, udp_len, 0))
    segment = bytes(udp_hdr) + reply_payload
    csum = _transport_checksum(original.ip_version, src_ip, dst_ip, IPPROTO_UDP, segment)
    struct.pack_into("!H", udp_hdr, 6, csum)
    ip_hdr = _build_ip_header(original.ip_version, src_ip, dst_ip, IPPROTO_UDP, udp_len)
    return ip_hdr + bytes(udp_hdr) + reply_payload


def build_udp_packet_same_direction(original: ParsedPacket, new_payload: bytes) -> bytes:
    """Substitui o payload de um pacote UDP mantendo origem/destino (ex.: bloqueio de CNAME inbound)."""
    udp_len = 8 + len(new_payload)
    udp_hdr = bytearray(struct.pack("!HHHH", original.src_port, original.dst_port, udp_len, 0))
    segment = bytes(udp_hdr) + new_payload
    csum = _transport_checksum(
        original.ip_version, original.src_ip, original.dst_ip, IPPROTO_UDP, segment
    )
    struct.pack_into("!H", udp_hdr, 6, csum)
    ip_hdr = _build_ip_header(
        original.ip_version, original.src_ip, original.dst_ip, IPPROTO_UDP, udp_len
    )
    return ip_hdr + bytes(udp_hdr) + new_payload


def build_tcp_rst_packet(original: ParsedPacket, to_client: bool = True) -> bytes:
    """Constrói pacote TCP RST para encerramento imediato (<1ms) de conexão bloqueada."""
    if to_client:
        src_ip = original.dst_ip
        dst_ip = original.src_ip
        src_port = original.dst_port
        dst_port = original.src_port
        seq = original.tcp_ack
        ack = (original.tcp_seq + max(1, len(original.payload))) & 0xFFFFFFFF
        flags = TCP_RST | TCP_ACK
    else:
        src_ip = original.src_ip
        dst_ip = original.dst_ip
        src_port = original.src_port
        dst_port = original.dst_port
        seq = original.tcp_seq
        ack = original.tcp_ack
        flags = TCP_RST

    tcp_hdr = bytearray(
        struct.pack(
            "!HHIIHHHH",
            src_port,
            dst_port,
            seq & 0xFFFFFFFF,
            ack & 0xFFFFFFFF,
            (5 << 12) | flags,
            0,
            0,
            0,
        )
    )
    csum = _transport_checksum(original.ip_version, src_ip, dst_ip, IPPROTO_TCP, bytes(tcp_hdr))
    struct.pack_into("!H", tcp_hdr, 16, csum)
    ip_hdr = _build_ip_header(original.ip_version, src_ip, dst_ip, IPPROTO_TCP, len(tcp_hdr))
    return ip_hdr + bytes(tcp_hdr)


HTTP_BLOCKED_RESPONSE = (
    b"HTTP/1.1 204 No Content\r\n"
    b"Connection: close\r\n"
    b"X-Qproxy-Blocked: 1\r\n\r\n"
)


def build_http_blocked_packet(original: ParsedPacket, response_body: bytes = HTTP_BLOCKED_RESPONSE) -> bytes:
    """Constrói resposta TCP PSH+ACK+FIN com HTTP 204 para encerrar requisição HTTP de anúncio sem espera."""
    src_ip = original.dst_ip
    dst_ip = original.src_ip
    src_port = original.dst_port
    dst_port = original.src_port
    seq = original.tcp_ack
    ack = (original.tcp_seq + len(original.payload)) & 0xFFFFFFFF
    flags = TCP_PSH | TCP_ACK | TCP_FIN

    tcp_hdr = bytearray(
        struct.pack(
            "!HHIIHHHH",
            src_port,
            dst_port,
            seq & 0xFFFFFFFF,
            ack & 0xFFFFFFFF,
            (5 << 12) | flags,
            65535,
            0,
            0,
        )
    )
    segment = bytes(tcp_hdr) + response_body
    csum = _transport_checksum(original.ip_version, src_ip, dst_ip, IPPROTO_TCP, segment)
    struct.pack_into("!H", tcp_hdr, 16, csum)
    ip_hdr = _build_ip_header(original.ip_version, src_ip, dst_ip, IPPROTO_TCP, len(segment))
    return ip_hdr + bytes(tcp_hdr) + response_body
