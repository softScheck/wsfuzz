"""Raw WebSocket frame construction and sending over TCP.

Bypasses the websockets library to send protocol-violating frames:
reserved opcodes, unmasked client frames, oversized control frames,
RSV bit abuse, fragmentation violations, payload length mismatches, etc.
"""

import asyncio
import base64
import contextlib
import hashlib
import os
import random
import ssl
import struct
import time
from dataclasses import dataclass
from urllib.parse import urlparse

from wsfuzz.transport import (
    ConnectOpts,
    TransportResult,
    classify_error,
    is_http_token,
    is_http_version,
    make_ssl_context,
    validate_connect_opts,
    validate_ws_uri,
)

# Standard opcodes
OP_CONTINUATION = 0x0
OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA

# Handshake headers to fuzz
_FUZZ_VERSIONS = ["13", "0", "99", "256", "-1", "a"]
_FUZZ_EXTENSIONS = [
    "",
    "permessage-deflate",
    "permessage-deflate; server_max_window_bits=8",
    "x-unknown-ext",
    "permessage-deflate; client_max_window_bits=0",
    "A" * 500,
]
_FUZZ_PROTOCOLS = ["", "chat", "graphql-ws", "mqtt", "x-invalid", "A" * 500]


@dataclass(frozen=True)
class HandshakeFuzz:
    version: str
    extension: str | None = None
    protocol: str | None = None


def make_handshake_fuzz(*, enabled: bool) -> HandshakeFuzz | None:
    if not enabled:
        return None
    extension = random.choice(_FUZZ_EXTENSIONS) or None
    protocol = random.choice(_FUZZ_PROTOCOLS) or None
    return HandshakeFuzz(
        version=random.choice(_FUZZ_VERSIONS),
        extension=extension,
        protocol=protocol,
    )


def build_frame(
    payload: bytes,
    opcode: int = OP_BINARY,
    *,
    fin: bool = True,
    mask: bool = True,
    rsv1: bool = False,
    rsv2: bool = False,
    rsv3: bool = False,
    fake_length: int | None = None,
) -> bytes:
    """Build a raw WebSocket frame with arbitrary parameters.

    If fake_length is set, the frame header declares that length instead of
    the actual payload length. This tests buffer pre-allocation bugs where
    servers allocate memory based on the declared length before reading.
    """
    first = (
        (0x80 if fin else 0)
        | (0x40 if rsv1 else 0)
        | (0x20 if rsv2 else 0)
        | (0x10 if rsv3 else 0)
        | (opcode & 0x0F)
    )

    length = fake_length if fake_length is not None else len(payload)
    if length < 0 or length > 2**64 - 1:
        raise ValueError("frame length must be between 0 and 2^64-1")
    if length < 126:
        header = struct.pack("!BB", first, (0x80 if mask else 0) | length)
    elif length < 65536:
        header = struct.pack("!BBH", first, (0x80 if mask else 0) | 126, length)
    else:
        header = struct.pack("!BBQ", first, (0x80 if mask else 0) | 127, length)

    if mask:
        mask_key = os.urandom(4)
        # Repeat mask key to payload length for efficient XOR
        full_mask = mask_key * (len(payload) // 4 + 1)
        masked = bytes(a ^ b for a, b in zip(payload, full_mask, strict=False))
        return header + mask_key + masked
    return header + payload


def _parse_close_frame(data: bytes, elapsed_ms: float = 0.0) -> TransportResult | None:
    """Try to parse a WebSocket close frame from raw response bytes.

    Returns a TransportResult with close_code/error if the response is a close
    frame with an error code (>= 1002), otherwise None.
    """
    if len(data) < 2:
        return None
    opcode = data[0] & 0x0F
    if opcode != OP_CLOSE:
        return None
    masked = bool(data[1] & 0x80)
    length = data[1] & 0x7F
    offset = 2
    if length == 126:
        if len(data) < 4:
            return None
        length = struct.unpack("!H", data[2:4])[0]
        offset = 4
    elif length == 127:
        if len(data) < 10:
            return None
        length = struct.unpack("!Q", data[2:10])[0]
        offset = 10
    if masked:
        offset += 4
    if length < 2 or len(data) < offset + 2:
        return None
    if masked:
        mask_key = data[offset - 4 : offset]
        code_bytes = bytes(data[offset + i] ^ mask_key[i % 4] for i in range(2))
        code = struct.unpack("!H", code_bytes)[0]
    else:
        code = struct.unpack("!H", data[offset : offset + 2])[0]
    if code >= 1002:
        return TransportResult(
            error=f"close code {code}",
            error_type=f"close_{code}",
            close_code=code,
            duration_ms=elapsed_ms,
        )
    return None


def _build_handshake(
    host: str,
    port: int,
    path: str,
    key: str,
    opts: ConnectOpts | None = None,
    *,
    handshake_fuzz: HandshakeFuzz | None = None,
) -> str:
    """Build the HTTP upgrade request for the WebSocket handshake."""
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {_format_host_header(host, port)}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        f"Sec-WebSocket-Version: {handshake_fuzz.version if handshake_fuzz else '13'}",
    ]
    if handshake_fuzz and handshake_fuzz.extension:
        lines.append(f"Sec-WebSocket-Extensions: {handshake_fuzz.extension}")
    if handshake_fuzz and handshake_fuzz.protocol:
        lines.append(f"Sec-WebSocket-Protocol: {handshake_fuzz.protocol}")
    if opts:
        if opts.origin:
            lines.append(f"Origin: {opts.origin}")
        for k, v in opts.headers.items():
            lines.append(f"{k}: {v}")
    lines.append("")
    lines.append("")
    return "\r\n".join(lines)


def _format_host_header(host: str, port: int) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def _request_target(parsed) -> str:
    path = parsed.path or "/"
    if parsed.query:
        return f"{path}?{parsed.query}"
    return path


def _handshake_status_error(response: bytes) -> str | None:
    status_line = response.split(b"\r\n", 1)[0]
    parts = status_line.split(None, 2)
    if len(parts) < 2 or not _is_http_version(parts[0]):
        return "malformed HTTP status line"
    if parts[1] != b"101":
        return "status is not 101"
    return None


def _is_http_version(value: bytes) -> bool:
    try:
        return is_http_version(value.decode("ascii"))
    except UnicodeDecodeError:
        return False


def _expected_accept(key: str) -> str:
    digest = hashlib.sha1(
        (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
    ).digest()
    return base64.b64encode(digest).decode()


def _parse_handshake_headers(response: bytes) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in response.split(b"\r\n")[1:]:
        if not line or b":" not in line:
            continue
        key, value = line.split(b":", 1)
        try:
            header_name = key.decode("ascii").lower()
            header_value = value.decode("ascii").strip()
        except UnicodeDecodeError:
            continue
        if not is_http_token(header_name):
            continue
        if header_name in headers:
            headers[header_name] = f"{headers[header_name]},{header_value}"
        else:
            headers[header_name] = header_value
    return headers


def _validate_handshake(response: bytes, key: str) -> str | None:
    status_error = _handshake_status_error(response)
    if status_error is not None:
        return status_error

    headers = _parse_handshake_headers(response)
    upgrade_tokens = {
        token.strip().lower()
        for token in headers.get("upgrade", "").split(",")
        if token.strip()
    }
    if "websocket" not in upgrade_tokens:
        return "missing Upgrade: websocket"

    connection_tokens = {
        token.strip().lower()
        for token in headers.get("connection", "").split(",")
        if token.strip()
    }
    if "upgrade" not in connection_tokens:
        return "missing Connection: Upgrade"

    if headers.get("sec-websocket-accept") != _expected_accept(key):
        return "invalid Sec-WebSocket-Accept"

    return None


async def send_raw(
    uri: str,
    frame: bytes,
    timeout: float = 5.0,
    opts: ConnectOpts | None = None,
    *,
    fuzz_handshake: bool = False,
    handshake_fuzz: HandshakeFuzz | None = None,
    ssl_context: ssl.SSLContext | None = None,
) -> TransportResult:
    """TCP connect, WS handshake, send raw frame, read response."""
    start = time.monotonic()

    def _elapsed() -> float:
        return (time.monotonic() - start) * 1000

    try:
        validate_ws_uri(uri)
        validate_connect_opts(opts)
        parsed = urlparse(uri)
        host = parsed.hostname
        assert host is not None  # validated by validate_ws_uri
        port = parsed.port or (443 if parsed.scheme == "wss" else 80)
        path = _request_target(parsed)
        tls_context = make_ssl_context(uri, opts, ssl_context)
        server_hostname = None
        if tls_context is not None:
            server_hostname = host
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(
                host,
                port,
                ssl=tls_context,
                server_hostname=server_hostname,
            )
            try:
                key = base64.b64encode(os.urandom(16)).decode()
                selected_handshake_fuzz = handshake_fuzz or make_handshake_fuzz(
                    enabled=fuzz_handshake
                )
                request = _build_handshake(
                    host,
                    port,
                    path,
                    key,
                    opts,
                    handshake_fuzz=selected_handshake_fuzz,
                )
                writer.write(request.encode())
                await writer.drain()

                response = await reader.readuntil(b"\r\n\r\n")
                handshake_error = _validate_handshake(response, key)
                if handshake_error is not None:
                    return TransportResult(
                        response=response,
                        error=(
                            f"handshake failed: {handshake_error}: "
                            f"{response[:80].decode(errors='replace')}"
                        ),
                        error_type="handshake_failed",
                        duration_ms=_elapsed(),
                    )

                writer.write(frame)
                await writer.drain()

                try:
                    data = await asyncio.wait_for(
                        reader.read(4096), timeout=min(timeout, 2.0)
                    )
                    if data:
                        close = _parse_close_frame(data, _elapsed())
                        if close:
                            return close
                        return TransportResult(response=data, duration_ms=_elapsed())
                    return TransportResult(duration_ms=_elapsed())
                except TimeoutError:
                    return TransportResult(duration_ms=_elapsed())
            finally:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()

    except Exception as e:
        return classify_error(e, _elapsed())
