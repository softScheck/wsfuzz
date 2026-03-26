"""HTTP-to-WebSocket harness for bridging traditional security tools.

Runs a local HTTP server that translates incoming HTTP POST bodies into
WebSocket messages, sends them to the target, and returns the WebSocket
response as the HTTP response body. This lets tools like SQLMap, ffuf,
Burp Scanner, or nuclei fuzz WebSocket endpoints over plain HTTP.

Usage:
    wsfuzz -t ws://target:8080/endpoint --harness
    wsfuzz -t ws://target:8080/endpoint --harness --harness-port 9999

Then point your tool at http://127.0.0.1:<port>:
    sqlmap -u "http://127.0.0.1:8765" --data='{"id": "1"}' --batch
    ffuf -u http://127.0.0.1:8765 -d 'FUZZ' -w wordlist.txt

The harness also supports a template with a [FUZZ] marker via --harness-template:
    wsfuzz -t ws://target/endpoint --harness --harness-template '{"user": "[FUZZ]"}'
    ffuf -u http://127.0.0.1:8765 -d 'FUZZ' -w wordlist.txt
    # The POST body replaces [FUZZ] in the template before sending over WS.
"""

import asyncio
import signal
from http import HTTPStatus

from wsfuzz.transport import ConnectOpts, send_payload

_FUZZ_MARKER = "[FUZZ]"


async def _handle_request(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    target: str,
    mode: str,
    timeout: float,
    opts: ConnectOpts | None,
    template: str | None,
) -> None:
    """Handle one HTTP request: read body, send over WS, return response."""
    try:
        headers_raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
    except (TimeoutError, ConnectionResetError, asyncio.IncompleteReadError):
        writer.close()
        return

    # Parse Content-Length to read the full body
    content_length = 0
    for line in headers_raw.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            content_length = int(line.split(b":", 1)[1].strip())
            break

    body = b""
    if content_length > 0:
        try:
            body = await asyncio.wait_for(
                reader.readexactly(content_length), timeout=10
            )
        except (TimeoutError, asyncio.IncompleteReadError):
            writer.close()
            return

    if template:
        payload = template.replace(_FUZZ_MARKER, body.decode(errors="replace")).encode()
    else:
        payload = body

    result = await send_payload(target, payload, mode, timeout, opts)

    if result.error:
        status = HTTPStatus.BAD_GATEWAY
        response_body = f"WS_ERROR [{result.error_type}]: {result.error}".encode()
    elif result.response:
        status = HTTPStatus.OK
        response_body = result.response
    else:
        status = HTTPStatus.NO_CONTENT
        response_body = b""

    http_response = (
        f"HTTP/1.1 {status.value} {status.phrase}\r\n"
        f"Content-Length: {len(response_body)}\r\n"
        f"Content-Type: application/octet-stream\r\n"
        f"Connection: close\r\n"
        f"X-WS-Duration-Ms: {result.duration_ms:.1f}\r\n"
    )
    if result.error_type:
        http_response += f"X-WS-Error-Type: {result.error_type}\r\n"
    if result.close_code:
        http_response += f"X-WS-Close-Code: {result.close_code}\r\n"
    http_response += "\r\n"

    writer.write(http_response.encode() + response_body)
    await writer.drain()
    writer.close()
    await writer.wait_closed()


async def run_harness(
    target: str,
    *,
    mode: str = "text",
    timeout: float = 5.0,
    opts: ConnectOpts | None = None,
    template: str | None = None,
    listen_host: str = "127.0.0.1",
    listen_port: int = 8765,
) -> None:
    """Start the HTTP-to-WebSocket harness server."""

    async def handler(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        await _handle_request(
            reader,
            writer,
            target=target,
            mode=mode,
            timeout=timeout,
            opts=opts,
            template=template,
        )

    server = await asyncio.start_server(handler, listen_host, listen_port)
    addr = server.sockets[0].getsockname()

    print("wsfuzz - HTTP-to-WebSocket Harness")
    print(f"listening:  http://{addr[0]}:{addr[1]}")
    print(f"target:     {target}")
    print(f"mode:       {mode}")
    if template:
        print(f"template:   {template}")
    print()
    print("Point your HTTP tools at the listen address.")
    print("POST body → WebSocket message → HTTP response")
    print()

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    async with server:
        await stop.wait()

    print("\nharness stopped")
