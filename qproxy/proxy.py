from __future__ import annotations

import asyncio
import logging
from urllib.parse import urlsplit

from .blocklist import RuleManager, normalize_host
from .config import Config
from .stats import StatsStore

LOG = logging.getLogger("qproxy")
MAX_HEADER = 64 * 1024


def _parse_host_port(value: str, default_port: int) -> tuple[str, int]:
    value = value.strip()
    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            raise ValueError("IPv6 inválido")
        host = value[1:end]
        rest = value[end + 1:]
        port = int(rest[1:]) if rest.startswith(":") else default_port
        return host, port
    if value.count(":") == 1:
        host, raw_port = value.rsplit(":", 1)
        if raw_port.isdigit():
            return host, int(raw_port)
    return value, default_port


def _split_headers(raw: bytes) -> tuple[str, str, str, list[tuple[str, str]]]:
    text = raw.decode("iso-8859-1")
    lines = text.split("\r\n")
    method, target, version = lines[0].split(" ", 2)
    headers = []
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers.append((name.strip(), value.strip()))
    return method.upper(), target, version, headers


def _header(headers: list[tuple[str, str]], name: str) -> str | None:
    lname = name.lower()
    for key, value in headers:
        if key.lower() == lname:
            return value
    return None


def _rewrite_http_request(method: str, target: str, version: str, headers: list[tuple[str, str]]) -> tuple[str, int, bytes]:
    parsed = urlsplit(target) if "://" in target else None
    host_header = _header(headers, "Host")

    if parsed and parsed.hostname:
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
    elif host_header:
        host, port = _parse_host_port(host_header, 80)
        path = target or "/"
    else:
        raise ValueError("Requisição sem Host")

    out = [f"{method} {path} {version}"]
    saw_connection = False
    for name, value in headers:
        low = name.lower()
        if low in {"proxy-connection", "proxy-authorization"}:
            continue
        if low == "connection":
            out.append("Connection: close")
            saw_connection = True
        else:
            out.append(f"{name}: {value}")
    if not saw_connection:
        out.append("Connection: close")
    out.extend(["", ""])
    return normalize_host(host), port, "\r\n".join(out).encode("iso-8859-1")


class ProxyServer:
    def __init__(self, config: Config, rules: RuleManager, stats: StatsStore):
        self.config = config
        self.rules = rules
        self.stats = stats

    async def serve(self) -> None:
        server = await asyncio.start_server(
            self.handle_client,
            self.config.listen_host,
            self.config.listen_port,
            limit=MAX_HEADER + 8192,
        )
        sockets = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
        LOG.info("Qproxy ouvindo em %s", sockets)
        async with server:
            await server.serve_forever()

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        try:
            raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=15)
            if len(raw) > MAX_HEADER:
                raise ValueError("Cabeçalho grande demais")
            method, target, version, headers = _split_headers(raw)
            if method == "CONNECT":
                await self._handle_connect(target, reader, writer)
            else:
                await self._handle_http(method, target, version, headers, reader, writer)
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass
        except asyncio.LimitOverrunError:
            await self._send_error(writer, 431, "Request Header Fields Too Large")
        except Exception as exc:
            LOG.debug("Erro com %s: %r", peer, exc)
            await self._send_error(writer, 502, "Bad Gateway")
        finally:
            if not writer.is_closing():
                writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_connect(self, target: str, client_r: asyncio.StreamReader, client_w: asyncio.StreamWriter) -> None:
        host, port = _parse_host_port(target, 443)
        host = normalize_host(host)
        decision = self.rules.evaluate(host)
        if decision.blocked:
            self.stats.record(host, "blocked", "https", decision.category, decision.rule)
            LOG.info("BLOCK HTTPS %s:%s [%s]", host, port, decision.category or "ad")
            await self._send_error(client_w, 403, "Blocked by Qproxy")
            return

        self.stats.record(host, "allowed", "https", rule=decision.rule)
        if self.config.log_allowed:
            LOG.info("ALLOW HTTPS %s:%s", host, port)
        upstream_r, upstream_w = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=self.config.connect_timeout_seconds,
        )
        client_w.write(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: Qproxy/0.2\r\n\r\n")
        await client_w.drain()
        relayed = await self._relay_bidirectional(client_r, client_w, upstream_r, upstream_w)
        self.stats.add_bytes(relayed)

    async def _handle_http(self, method: str, target: str, version: str, headers: list[tuple[str, str]], client_r: asyncio.StreamReader, client_w: asyncio.StreamWriter) -> None:
        host, port, rewritten = _rewrite_http_request(method, target, version, headers)
        decision = self.rules.evaluate(host)
        if decision.blocked:
            self.stats.record(host, "blocked", "http", decision.category, decision.rule)
            LOG.info("BLOCK HTTP %s %s [%s]", host, target, decision.category or "ad")
            client_w.write(
                b"HTTP/1.1 204 No Content\r\n"
                b"Connection: close\r\n"
                b"X-Qproxy-Blocked: 1\r\n\r\n"
            )
            await client_w.drain()
            return

        self.stats.record(host, "allowed", "http", rule=decision.rule)
        if self.config.log_allowed:
            LOG.info("ALLOW HTTP %s %s", host, target)
        upstream_r, upstream_w = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=self.config.connect_timeout_seconds,
        )
        upstream_w.write(rewritten)
        await upstream_w.drain()
        relayed = await self._relay_bidirectional(client_r, client_w, upstream_r, upstream_w)
        self.stats.add_bytes(relayed)

    async def _relay_bidirectional(self, a_r, a_w, b_r, b_w) -> int:
        async def pump(src, dst):
            total = 0
            try:
                while True:
                    chunk = await src.read(64 * 1024)
                    if not chunk:
                        break
                    dst.write(chunk)
                    await dst.drain()
                    total += len(chunk)
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                pass
            finally:
                # A direção de envio terminou, mas a outra pode ainda
                # receber a resposta (HTTP POST, streaming, imagens).
                # Uma desconexão parcial NÃO deve cancelar a outra direção.
                if not dst.is_closing() and dst.can_write_eof():
                    try:
                        dst.write_eof()
                        await dst.drain()
                    except (OSError, RuntimeError):
                        pass
            return total

        tasks = (
            asyncio.create_task(pump(a_r, b_w)),
            asyncio.create_task(pump(b_r, a_w)),
        )
        try:
            # FIRST_COMPLETED + cancel() cortava downloads assim que
            # o cliente concluía o envio da requisição.
            results = await asyncio.gather(*tasks)
            return sum(results)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            if not b_w.is_closing():
                b_w.close()
                try:
                    await b_w.wait_closed()
                except (OSError, ConnectionResetError, BrokenPipeError):
                    pass

    @staticmethod
    async def _send_error(writer: asyncio.StreamWriter, status: int, message: str) -> None:
        if writer.is_closing():
            return
        body = f"{status} {message}\n".encode()
        response = (
            f"HTTP/1.1 {status} {message}\r\n"
            f"Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("ascii") + body
        writer.write(response)
        try:
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
