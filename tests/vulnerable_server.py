"""Intentionally vulnerable WebSocket server for security testing.

Each path simulates a real-world vulnerability class. The fuzzer should
detect all of these by observing crashes, error close codes, or connection
resets when sending malicious payloads.

These are deliberately insecure — for authorized testing only.
"""

import json
import re
import struct
from collections.abc import Awaitable, Callable

import websockets
from websockets import ServerConnection


async def vulnerable_handler(ws: ServerConnection) -> None:
    path = ws.request.path if ws.request else "/"

    handlers: dict[str, Callable[[ServerConnection], Awaitable[None]]] = {
        "/json-parse": _json_parse,
        "/overflow": _buffer_overflow,
        "/format-string": _format_string,
        "/null-byte": _null_byte,
        "/int-overflow": _integer_overflow,
        "/dos-regex": _regex_dos,
        "/type-confusion": _type_confusion,
    }

    handler = handlers.get(path, _echo)
    await handler(ws)


async def _echo(ws: ServerConnection) -> None:
    async for msg in ws:
        await ws.send(msg)


async def _json_parse(ws: ServerConnection) -> None:
    """Vulnerability: unhandled exception on malformed JSON."""
    async for msg in ws:
        if isinstance(msg, bytes):
            msg = msg.decode(errors="replace")
        data = json.loads(msg)
        await ws.send(json.dumps({"status": "ok", "received": data}))


async def _buffer_overflow(ws: ServerConnection) -> None:
    """Vulnerability: crash on oversized input."""
    async for msg in ws:
        if isinstance(msg, str):
            msg = msg.encode()
        assert len(msg) <= 128, f"buffer overflow: {len(msg)} > 128"
        await ws.send(msg)


async def _format_string(ws: ServerConnection) -> None:
    """Vulnerability: user input in format string."""
    async for msg in ws:
        if isinstance(msg, bytes):
            msg = msg.decode(errors="replace")
        result = msg.format(user="admin", role="user")
        await ws.send(result)


async def _null_byte(ws: ServerConnection) -> None:
    """Vulnerability: null byte injection."""
    async for msg in ws:
        if isinstance(msg, bytes):
            msg = msg.decode()
        parts = msg.split("\x00")
        response = f"first={parts[0]}, second={parts[1]}"
        await ws.send(response)


async def _integer_overflow(ws: ServerConnection) -> None:
    """Vulnerability: integer parsing without validation."""
    async for msg in ws:
        if isinstance(msg, bytes):
            msg = msg.decode(errors="replace")
        value = int(msg.strip())
        packed = struct.pack(">i", value)
        await ws.send(packed)


# Evil regex with catastrophic backtracking on inputs like "aaa...!"
_REDOS_PATTERN = re.compile(r"^(a+)+$")


async def _regex_dos(ws: ServerConnection) -> None:
    """Vulnerability: ReDoS via catastrophic backtracking."""
    async for msg in ws:
        if isinstance(msg, bytes):
            msg = msg.decode(errors="replace")
        match = _REDOS_PATTERN.match(msg)
        await ws.send("match" if match else "no match")


async def _type_confusion(ws: ServerConnection) -> None:
    """Vulnerability: type confusion in message handling."""
    async for msg in ws:
        if isinstance(msg, bytes):
            msg = msg.decode(errors="replace")
        data = json.loads(msg)
        name = data["name"]
        action = data["action"]
        await ws.send(f"Hello {name}, executing {action}")


async def start_vulnerable_server(
    host: str = "127.0.0.1", port: int = 0
) -> websockets.Server:
    return await websockets.serve(vulnerable_handler, host, port)
