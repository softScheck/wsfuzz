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
import json
import logging
import re
import signal
from dataclasses import dataclass
from functools import lru_cache
from http import HTTPStatus
from urllib.parse import parse_qs, urlsplit

from wsfuzz.transport import (
    ConnectOpts,
    contains_control_chars,
    is_http_token,
    is_http_version,
    send_payload,
)

logger = logging.getLogger(__name__)

_FUZZ_MARKER = "[FUZZ]"
_TEMPLATE_MARKER_RE = re.compile(
    r"\[(FUZZ|METHOD|PATH|(HEADER|HEADERS|QUERY|QUERIES):([^\]]+))\]"
)
_MAX_HARNESS_BODY_BYTES = 10 * 1024 * 1024


@dataclass
class HarnessRequest:
    method: str
    path: str
    query: dict[str, list[str]]
    headers: dict[str, list[str]]
    body: bytes


class HarnessTemplateError(ValueError):
    pass


class HarnessBodyTooLargeError(ValueError):
    pass


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
    try:
        writer.write(_build_response(status, body, headers=headers))
        await writer.drain()
    except (BrokenPipeError, ConnectionResetError):
        return
    finally:
        writer.close()
        with contextlib.suppress(BrokenPipeError, ConnectionResetError, OSError):
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
        if key != key.strip():
            return None
        key = key.lower()
        if not key or not is_http_token(key):
            return None
        value = value.strip()
        if contains_control_chars(value):
            return None
        headers.setdefault(key, []).append(value)

    return lines[0], headers


async def _read_chunked_body(reader: asyncio.StreamReader) -> bytes:
    chunks: list[bytes] = []
    total_size = 0
    while True:
        line = await asyncio.wait_for(reader.readuntil(b"\r\n"), timeout=10)
        size_raw = line[:-2].split(b";", 1)[0]
        try:
            size = int(size_raw.decode("ascii"), 16)
        except ValueError as exc:
            raise ValueError("invalid chunk size") from exc
        if size < 0:
            raise ValueError("invalid chunk size")
        if size == 0:
            while True:
                trailer = await asyncio.wait_for(reader.readuntil(b"\r\n"), timeout=10)
                if trailer == b"\r\n":
                    return b"".join(chunks)
        total_size += size
        if total_size > _MAX_HARNESS_BODY_BYTES:
            raise HarnessBodyTooLargeError("request body too large")
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
    except (
        ConnectionResetError,
        asyncio.IncompleteReadError,
        asyncio.LimitOverrunError,
    ):
        return None, HTTPStatus.BAD_REQUEST

    parsed = _parse_headers(headers_raw[:-4])
    if parsed is None:
        return None, HTTPStatus.BAD_REQUEST
    request_line, headers = parsed

    parts = request_line.split()
    if len(parts) != 3 or not is_http_version(parts[2]):
        return None, HTTPStatus.BAD_REQUEST
    method, target, _version = parts
    if method.upper() != "POST":
        return None, HTTPStatus.METHOD_NOT_ALLOWED

    transfer_encoding_tokens = [
        token.strip().lower()
        for value in headers.get("transfer-encoding", [])
        for token in value.split(",")
        if token.strip()
    ]
    try:
        if transfer_encoding_tokens == ["chunked"]:
            body = await _read_chunked_body(reader)
        else:
            if transfer_encoding_tokens:
                return None, HTTPStatus.NOT_IMPLEMENTED
            if "content-length" not in headers:
                return None, HTTPStatus.LENGTH_REQUIRED
            content_lengths = headers["content-length"]
            if len(set(content_lengths)) != 1 or not content_lengths[0].isdigit():
                return None, HTTPStatus.BAD_REQUEST
            content_length = int(content_lengths[0])
            if content_length > _MAX_HARNESS_BODY_BYTES:
                return None, HTTPStatus.REQUEST_ENTITY_TOO_LARGE

            body = b""
            if content_length:
                body = await asyncio.wait_for(
                    reader.readexactly(content_length), timeout=10
                )
    except TimeoutError:
        return None, HTTPStatus.REQUEST_TIMEOUT
    except HarnessBodyTooLargeError:
        return None, HTTPStatus.REQUEST_ENTITY_TOO_LARGE
    except (ValueError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
        return None, HTTPStatus.BAD_REQUEST

    try:
        split = urlsplit(target)
    except ValueError:
        return None, HTTPStatus.BAD_REQUEST
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


def _apply_template(
    template: str,
    request: HarnessRequest,
    mode: str,
    template_format: str = "raw",
) -> bytes:
    if template_format == "json":
        return _apply_json_template(template, request, mode)
    if template_format != "raw":
        raise HarnessTemplateError("unsupported harness template format")
    if mode == "binary" and template == _FUZZ_MARKER:
        return request.body

    def replace_marker(match: re.Match[str]) -> str:
        return _marker_value(match, request, mode)

    return _TEMPLATE_MARKER_RE.sub(replace_marker, template).encode()


def _apply_json_template(template: str, request: HarnessRequest, mode: str) -> bytes:
    parsed = _parse_json_template(template)
    rendered = _render_json_template_value(parsed, request, mode)
    return json.dumps(rendered, separators=(",", ":"), ensure_ascii=False).encode()


@lru_cache(maxsize=128)
def _parse_json_template(template: str):
    try:
        return json.loads(template)
    except json.JSONDecodeError as exc:
        raise HarnessTemplateError("JSON harness template is not valid JSON") from exc


def _render_json_template_value(value, request: HarnessRequest, mode: str):
    if isinstance(value, dict):
        return {
            _render_json_template_key(
                str(key), request, mode
            ): _render_json_template_value(
                item,
                request,
                mode,
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_render_json_template_value(item, request, mode) for item in value]
    if not isinstance(value, str):
        return value
    full_match = _TEMPLATE_MARKER_RE.fullmatch(value)
    if full_match:
        return _marker_value(full_match, request, mode)
    return _TEMPLATE_MARKER_RE.sub(
        lambda match: _marker_value(match, request, mode),
        value,
    )


def _render_json_template_key(key: str, request: HarnessRequest, mode: str) -> str:
    return _TEMPLATE_MARKER_RE.sub(
        lambda match: _marker_value(match, request, mode),
        key,
    )


def _marker_value(match: re.Match[str], request: HarnessRequest, mode: str) -> str:
    token = match.group(1)
    kind = match.group(2)
    key = match.group(3)
    if token == "FUZZ":
        if mode == "binary":
            try:
                return request.body.decode()
            except UnicodeDecodeError as exc:
                raise HarnessTemplateError(
                    "binary [FUZZ] payload cannot be interpolated inside a text template"
                ) from exc
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


async def _handle_request(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    target: str,
    mode: str,
    timeout: float,
    opts: ConnectOpts | None,
    template: str | None,
    template_format: str = "raw",
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
    try:
        payload = (
            _apply_template(template, request, mode, template_format)
            if template
            else request.body
        )
    except HarnessTemplateError as exc:
        await _send_response(writer, HTTPStatus.BAD_REQUEST, str(exc).encode())
        return

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
    template_format: str = "raw",
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
            template_format=template_format,
        )

    server = await asyncio.start_server(handler, listen_host, listen_port)
    addr = server.sockets[0].getsockname()

    logger.info("wsfuzz - HTTP-to-WebSocket Harness")
    logger.info(f"listening:  http://{addr[0]}:{addr[1]}")
    logger.info(f"target:     {target}")
    logger.info(f"mode:       {mode}")
    if template:
        logger.info(f"template:   {template}")
        logger.info(f"template-format: {template_format}")
    logger.info("")
    logger.info("Point your HTTP tools at the listen address.")
    logger.info("POST body → WebSocket message → HTTP response")
    logger.info("")

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop.set)

    async with server:
        await stop.wait()

    logger.info("harness stopped")
