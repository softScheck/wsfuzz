"""Raw WebSocket frame construction and sending over TCP.

Bypasses the websockets library to send protocol-violating frames:
reserved opcodes, unmasked client frames, oversized control frames,
RSV bit abuse, fragmentation violations, payload length mismatches, etc.
"""

import asyncio
import base64
import os
import random
import struct
import time
from urllib.parse import urlparse

from wsfuzz.transport import ConnectOpts, TransportResult

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
    if length < 126:
        header = struct.pack("!BB", first, (0x80 if mask else 0) | length)
    elif length < 65536:
        header = struct.pack("!BBH", first, (0x80 if mask else 0) | 126, length)
    else:
        header = struct.pack("!BBQ", first, (0x80 if mask else 0) | 127, length)

    if mask:
        mask_key = os.urandom(4)
        masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
        return header + mask_key + masked
    return header + payload


def _parse_close_frame(data: bytes) -> TransportResult | None:
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
        )
    return None


def _build_handshake(
    host: str,
    port: int,
    path: str,
    key: str,
    opts: ConnectOpts | None = None,
    *,
    fuzz_handshake: bool = False,
) -> str:
    """Build the HTTP upgrade request for the WebSocket handshake."""
    version = random.choice(_FUZZ_VERSIONS) if fuzz_handshake else "13"
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}:{port}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        f"Sec-WebSocket-Version: {version}",
    ]
    if fuzz_handshake:
        ext = random.choice(_FUZZ_EXTENSIONS)
        if ext:
            lines.append(f"Sec-WebSocket-Extensions: {ext}")
        proto = random.choice(_FUZZ_PROTOCOLS)
        if proto:
            lines.append(f"Sec-WebSocket-Protocol: {proto}")
    if opts:
        if opts.origin:
            lines.append(f"Origin: {opts.origin}")
        for k, v in opts.headers.items():
            lines.append(f"{k}: {v}")
    lines.append("")
    lines.append("")
    return "\r\n".join(lines)


async def send_raw(
    uri: str,
    frame: bytes,
    timeout: float = 5.0,
    opts: ConnectOpts | None = None,
    *,
    fuzz_handshake: bool = False,
) -> TransportResult:
    """TCP connect, WS handshake, send raw frame, read response."""
    parsed = urlparse(uri)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "wss" else 80)
    path = parsed.path or "/"
    start = time.monotonic()

    def _elapsed() -> float:
        return (time.monotonic() - start) * 1000

    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(host, port)
            try:
                key = base64.b64encode(os.urandom(16)).decode()
                request = _build_handshake(
                    host, port, path, key, opts, fuzz_handshake=fuzz_handshake
                )
                writer.write(request.encode())
                await writer.drain()

                response = await reader.readuntil(b"\r\n\r\n")
                if b"101" not in response:
                    return TransportResult(
                        error=f"handshake failed: {response[:80].decode(errors='replace')}",
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
                        close = _parse_close_frame(data)
                        if close:
                            close.duration_ms = _elapsed()
                            return close
                        return TransportResult(response=data, duration_ms=_elapsed())
                    return TransportResult(duration_ms=_elapsed())
                except TimeoutError:
                    return TransportResult(duration_ms=_elapsed())
            finally:
                writer.close()
                await writer.wait_closed()

    except ConnectionRefusedError:
        return TransportResult(
            error="connection refused",
            error_type="connection_refused",
            duration_ms=_elapsed(),
            connection_refused=True,
        )
    except ConnectionResetError:
        return TransportResult(
            error="connection reset by server",
            error_type="connection_reset",
            duration_ms=_elapsed(),
        )
    except TimeoutError:
        return TransportResult(
            error="timeout", error_type="timeout", duration_ms=_elapsed()
        )
    except Exception as e:
        return TransportResult(
            error=str(e), error_type=type(e).__name__, duration_ms=_elapsed()
        )
