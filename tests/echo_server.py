"""Simple WebSocket echo server for testing.

Supports multiple behaviors based on the path:
  /echo      - echoes back whatever it receives
  /close     - accepts connection then immediately closes
  /error     - accepts connection then closes with error code
  /slow      - waits 10s before responding (for timeout testing)
  /           - default echo
"""

import asyncio
import json
import ssl

import websockets
from websockets import ServerConnection

_reuse_connection_count = 0


def reset_server_state() -> None:
    global _reuse_connection_count
    _reuse_connection_count = 0


def reuse_connection_count() -> int:
    return _reuse_connection_count


async def echo_handler(ws: ServerConnection) -> None:
    path = ws.request.path if ws.request else "/"

    if path == "/close":
        await ws.close()
        return

    if path == "/error":
        await ws.close(1011, "internal error")
        return

    if path == "/slow":
        try:
            msg = await ws.recv()
            await asyncio.sleep(10)
            await ws.send(msg)
        except websockets.ConnectionClosed:
            pass
        return

    if path == "/stateful":
        await _stateful_handler(ws)
        return

    if path == "/header-auth":
        await _header_auth_handler(ws)
        return

    if path == "/reuse":
        await _reuse_handler(ws)
        return

    async for msg in ws:
        await ws.send(msg)


async def _stateful_handler(ws: ServerConnection) -> None:
    if not ws.request or ws.request.headers.get("Authorization") != "Bearer stage2":
        await ws.close(1008, "auth required")
        return

    logged_in = False
    subscribed = False
    session_id = "session-42"

    async for msg in ws:
        if isinstance(msg, bytes):
            msg = msg.decode(errors="replace")
        data = json.loads(msg)
        op = data.get("op")
        if op == "login" and data.get("user") == "test" and data.get("pass") == "test":
            logged_in = True
            await ws.send(json.dumps({"ok": True, "token": "ws-token"}))
            continue
        if op == "subscribe" and logged_in and data.get("topic") == "orders":
            subscribed = True
            await ws.send(
                json.dumps({"ok": True, "session": session_id, "status": "subscribed"})
            )
            continue
        if op == "update" and logged_in and subscribed:
            await ws.send(
                json.dumps(
                    {
                        "ok": True,
                        "echo": data.get("id"),
                        "session": data.get("session"),
                    }
                )
            )
            continue
        await ws.close(1008, "invalid state")
        return


async def _header_auth_handler(ws: ServerConnection) -> None:
    if not ws.request or ws.request.headers.get("Authorization") != "Bearer stage2":
        await ws.close(1008, "auth required")
        return

    async for msg in ws:
        await ws.send(msg)


async def _reuse_handler(ws: ServerConnection) -> None:
    global _reuse_connection_count
    _reuse_connection_count += 1
    connection_id = f"conn-{_reuse_connection_count}"

    async for msg in ws:
        if isinstance(msg, bytes):
            msg = msg.decode(errors="replace")
        data = json.loads(msg)
        op = data.get("op")
        if op == "hello":
            await ws.send(json.dumps({"connection_id": connection_id}))
            continue
        if op == "ping":
            await ws.send(
                json.dumps({"connection_id": connection_id, "echo": data.get("value")})
            )
            continue
        await ws.close(1008, "unsupported op")
        return


async def start_server(
    host: str = "127.0.0.1",
    port: int = 0,
    *,
    ssl_context: ssl.SSLContext | None = None,
) -> websockets.Server:
    return await websockets.serve(echo_handler, host, port, ssl=ssl_context)
