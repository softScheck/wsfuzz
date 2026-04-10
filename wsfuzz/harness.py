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

Additional markers are supported for HTTP-driven templating:
    [HEADER:Name]  - inserts the incoming HTTP header value
    [QUERY:name]   - inserts the first query-string value from the HTTP request
"""

import asyncio
import contextlib
import re
import signal
from dataclasses import dataclass
from http import HTTPStatus
from urllib.parse import parse_qs, urlsplit

from wsfuzz.transport import ConnectOpts, send_payload

_FUZZ_MARKER = "[FUZZ]"
_TEMPLATE_MARKER_RE = re.compile(
    r"\[(FUZZ|METHOD|PATH|(HEADER|HEADERS|QUERY|QUERIES):([^\]]+))\]"
)


@dataclass
class HarnessRequest:
    method: str
    path: str
    query: dict[str, list[str]]
    headers: dict[str, list[str]]
    body: bytes


def _build_response(
    status: HTTPStatus,
    body: bytes = b"",
    *,
    headers: dict[str, str] | None = None,
) -> bytes:
    header_lines = {
        "Content-Length": str(len(body)),
        "Content-Type": "application/octet-stream",
        "Connection": "close",
    }
    if headers:
        header_lines.update(headers)
    response = [f"HTTP/1.1 {status.value} {status.phrase}"]
    response.extend(f"{key}: {value}" for key, value in header_lines.items())
    response.append("")
    response.append("")
    return "\r\n".join(response).encode() + body


async def _send_response(
    writer: asyncio.StreamWriter,
    status: HTTPStatus,
    body: bytes = b"",
    *,
    headers: dict[str, str] | None = None,
) -> None:
    writer.write(_build_response(status, body, headers=headers))
    await writer.drain()
    writer.close()
    await writer.wait_closed()


def _parse_headers(headers_raw: bytes) -> tuple[str, dict[str, list[str]]] | None:
    try:
        text = headers_raw.decode("iso-8859-1")
    except UnicodeDecodeError:
        return None

    lines = text.split("\r\n")
    if not lines or not lines[0]:
        return None

    headers: dict[str, list[str]] = {}
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line:
            return None
        key, value = line.split(":", 1)
        headers.setdefault(key.strip().lower(), []).append(value.strip())

    return lines[0], headers


async def _read_chunked_body(reader: asyncio.StreamReader) -> bytes:
    chunks: list[bytes] = []
    while True:
        line = await asyncio.wait_for(reader.readuntil(b"\r\n"), timeout=10)
        size_raw = line[:-2].split(b";", 1)[0]
        try:
            size = int(size_raw.decode("ascii"), 16)
        except ValueError as exc:
            raise ValueError("invalid chunk size") from exc
        if size == 0:
            while True:
                trailer = await asyncio.wait_for(reader.readuntil(b"\r\n"), timeout=10)
                if trailer == b"\r\n":
                    return b"".join(chunks)
        chunks.append(await asyncio.wait_for(reader.readexactly(size), timeout=10))
        if await asyncio.wait_for(reader.readexactly(2), timeout=10) != b"\r\n":
            raise ValueError("invalid chunk terminator")


async def _read_request(
    reader: asyncio.StreamReader,
) -> tuple[HarnessRequest | None, HTTPStatus | None]:
    try:
        headers_raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
    except TimeoutError:
        return None, HTTPStatus.REQUEST_TIMEOUT
    except (ConnectionResetError, asyncio.IncompleteReadError):
        return None, HTTPStatus.BAD_REQUEST

    parsed = _parse_headers(headers_raw[:-4])
    if parsed is None:
        return None, HTTPStatus.BAD_REQUEST
    request_line, headers = parsed

    parts = request_line.split()
    if len(parts) != 3 or not parts[2].startswith("HTTP/"):
        return None, HTTPStatus.BAD_REQUEST
    method, target, _version = parts
    if method.upper() != "POST":
        return None, HTTPStatus.METHOD_NOT_ALLOWED

    transfer_encoding = ",".join(headers.get("transfer-encoding", [])).lower()
    try:
        if "chunked" in transfer_encoding:
            body = await _read_chunked_body(reader)
        else:
            if transfer_encoding:
                return None, HTTPStatus.NOT_IMPLEMENTED
            if "content-length" not in headers:
                return None, HTTPStatus.LENGTH_REQUIRED
            try:
                content_length = int(headers["content-length"][-1])
            except ValueError:
                return None, HTTPStatus.BAD_REQUEST
            if content_length < 0:
                return None, HTTPStatus.BAD_REQUEST

            body = b""
            if content_length:
                body = await asyncio.wait_for(
                    reader.readexactly(content_length), timeout=10
                )
    except TimeoutError:
        return None, HTTPStatus.REQUEST_TIMEOUT
    except (ValueError, asyncio.IncompleteReadError):
        return None, HTTPStatus.BAD_REQUEST

    split = urlsplit(target)
    query = parse_qs(split.query, keep_blank_values=True)
    return (
        HarnessRequest(
            method=method.upper(),
            path=split.path or "/",
            query=query,
            headers=headers,
            body=body,
        ),
        None,
    )


def _apply_template(template: str, request: HarnessRequest) -> bytes:
    def replace_marker(match: re.Match[str]) -> str:
        token = match.group(1)
        kind = match.group(2)
        key = match.group(3)
        if token == "FUZZ":
            return request.body.decode(errors="replace")
        if token == "METHOD":
            return request.method
        if token == "PATH":
            return request.path
        if kind == "HEADER":
            return request.headers.get(key.lower(), [""])[0]
        if kind == "HEADERS":
            return ",".join(request.headers.get(key.lower(), []))
        if kind == "QUERY":
            return request.query.get(key, [""])[0]
        return ",".join(request.query.get(key, []))

    return _TEMPLATE_MARKER_RE.sub(replace_marker, template).encode()


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
    request, error_status = await _read_request(reader)
    if error_status is not None:
        extra_headers = (
            {"Allow": "POST"} if error_status == HTTPStatus.METHOD_NOT_ALLOWED else None
        )
        await _send_response(
            writer,
            error_status,
            error_status.phrase.encode(),
            headers=extra_headers,
        )
        return

    assert request is not None
    payload = _apply_template(template, request) if template else request.body

    result = await send_payload(target, payload, mode, timeout, opts)

    if result.error:
        status = HTTPStatus.BAD_GATEWAY
        response_body = f"WS_ERROR [{result.error_type}]: {result.error}".encode()
    elif result.response is not None:
        status = HTTPStatus.OK
        response_body = result.response
    else:
        status = HTTPStatus.NO_CONTENT
        response_body = b""

    response_headers = {"X-WS-Duration-Ms": f"{result.duration_ms:.1f}"}
    if result.error_type:
        response_headers["X-WS-Error-Type"] = result.error_type
    if result.close_code:
        response_headers["X-WS-Close-Code"] = str(result.close_code)
    await _send_response(
        writer,
        status,
        response_body,
        headers=response_headers,
    )


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
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop.set)

    async with server:
        await stop.wait()

    print("\nharness stopped")
