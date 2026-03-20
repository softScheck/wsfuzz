"""Simple WebSocket echo server for testing.

Supports multiple behaviors based on the path:
  /echo      - echoes back whatever it receives
  /close     - accepts connection then immediately closes
  /error     - accepts connection then closes with error code
  /slow      - waits 10s before responding (for timeout testing)
  /           - default echo
"""

import asyncio

import websockets
from websockets import ServerConnection


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

    async for msg in ws:
        await ws.send(msg)


async def start_server(host: str = "127.0.0.1", port: int = 0) -> websockets.Server:
    return await websockets.serve(echo_handler, host, port)
