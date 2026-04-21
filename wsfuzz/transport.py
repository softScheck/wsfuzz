import asyncio
import errno
import re
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import websockets

_HTTP_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_CONTROL_CHARS = frozenset(
    chr(code)
    for code in [*range(0x00, 0x09), *range(0x0B, 0x0D), *range(0x0E, 0x20), 0x7F]
)


class TransportConfigError(ValueError):
    pass


@dataclass
class TransportResult:
    response: bytes | None = None
    error: str | None = None
    error_type: str | None = None
    close_code: int | None = None
    duration_ms: float = 0.0
    connection_refused: bool = False


def validate_ws_uri(uri: str) -> None:
    if any(char in uri for char in "\r\n"):
        raise ValueError("target must not contain newlines")
    if any(char in uri for char in " \t"):
        raise ValueError("target must not contain whitespace")
    if contains_control_chars(uri):
        raise ValueError("target must not contain control characters")
    try:
        parsed = urlparse(uri)
    except ValueError as exc:
        raise ValueError("target must be a valid ws:// or wss:// URL") from exc
    if parsed.scheme not in {"ws", "wss"} or not parsed.netloc:
        raise ValueError("target must be a ws:// or wss:// URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("target must not contain userinfo")
    if parsed.hostname is None:
        raise ValueError("target must include a host")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("target port must be between 1 and 65535") from exc
    if port == 0:
        raise ValueError("target port must be between 1 and 65535")
    if parsed.fragment:
        raise ValueError("target must not contain fragments")


def is_http_token(value: str) -> bool:
    return _HTTP_TOKEN_RE.fullmatch(value) is not None


def is_http_version(value: str) -> bool:
    prefix, separator, version = value.partition("/")
    if prefix != "HTTP" or separator != "/":
        return False
    major, dot, minor = version.partition(".")
    return bool(major and dot == "." and minor and major.isdigit() and minor.isdigit())


def contains_control_chars(value: str) -> bool:
    return any(char in _CONTROL_CHARS for char in value)


def handle_close(e: websockets.ConnectionClosed, elapsed_ms: float) -> TransportResult:
    code = e.rcvd.code if e.rcvd else None
    reason = e.rcvd.reason if e.rcvd else ""
    if code and code >= 1002:
        return TransportResult(
            error=f"close code {code}: {reason}",
            error_type=f"close_{code}",
            close_code=code,
            duration_ms=elapsed_ms,
        )
    return TransportResult(close_code=code, duration_ms=elapsed_ms)


def _is_oserror_refused(e: OSError, err_str: str) -> bool:
    if getattr(e, "errno", None) == errno.ECONNREFUSED:
        return True
    for ex in getattr(e, "exceptions", ()):
        if getattr(ex, "errno", None) == errno.ECONNREFUSED:
            return True
    return "Connect call failed" in err_str or "Connection refused" in err_str


def classify_error(e: Exception, elapsed_ms: float) -> TransportResult:
    """Classify a network exception into a TransportResult.

    Shared by both normal (websockets) and raw (TCP) transport so that
    error classification stays consistent across modes.
    """
    if isinstance(e, TransportConfigError):
        return TransportResult(
            error=str(e),
            error_type="transport_config",
            duration_ms=elapsed_ms,
        )
    if isinstance(e, ConnectionRefusedError):
        return TransportResult(
            error="connection refused",
            error_type="connection_refused",
            duration_ms=elapsed_ms,
            connection_refused=True,
        )
    if isinstance(e, ConnectionResetError):
        return TransportResult(
            error="connection reset by server",
            error_type="connection_reset",
            duration_ms=elapsed_ms,
        )
    if isinstance(e, TimeoutError):
        return TransportResult(
            error="timeout",
            error_type="timeout",
            duration_ms=elapsed_ms,
        )
    if isinstance(e, OSError):
        err_str = str(e)
        is_refused = _is_oserror_refused(e, err_str)
        return TransportResult(
            error=err_str,
            error_type="connection_refused" if is_refused else "OSError",
            duration_ms=elapsed_ms,
            connection_refused=is_refused,
        )
    return TransportResult(
        error=str(e),
        error_type=type(e).__name__,
        duration_ms=elapsed_ms,
    )


@dataclass
class ConnectOpts:
    """Extra options for WebSocket connections."""

    headers: dict[str, str] = field(default_factory=dict)
    origin: str | None = None
    ca_file: str | None = None
    insecure: bool = False


def make_connect_opts(
    headers: dict[str, str] | None = None,
    origin: str | None = None,
    *,
    ca_file: str | None = None,
    insecure: bool = False,
) -> ConnectOpts | None:
    """Create ConnectOpts only when custom handshake options are present."""
    if not headers and origin is None and ca_file is None and not insecure:
        return None
    opts = ConnectOpts(
        headers=dict(headers or {}),
        origin=origin,
        ca_file=ca_file,
        insecure=insecure,
    )
    validate_connect_opts(opts)
    return opts


def validate_connect_opts(opts: ConnectOpts | None) -> None:
    if opts is None:
        return
    _validate_connect_headers(opts.headers)
    if opts.origin is not None:
        if any(char in opts.origin for char in "\r\n"):
            raise TransportConfigError("origin must not contain newlines")
        if contains_control_chars(opts.origin):
            raise TransportConfigError("origin must not contain control characters")


def _validate_connect_headers(headers: dict[str, str]) -> None:
    for key, value in headers.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise TransportConfigError("headers must be strings")
        if not key.strip():
            raise TransportConfigError("header names must not be empty")
        if not is_http_token(key):
            raise TransportConfigError("header names must be valid HTTP tokens")
        if any(char in value for char in "\r\n"):
            raise TransportConfigError("headers must not contain newlines")
        if contains_control_chars(value):
            raise TransportConfigError("headers must not contain control characters")


def make_insecure_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def make_ssl_context(
    uri: str,
    opts: ConnectOpts | None = None,
    override: ssl.SSLContext | None = None,
) -> ssl.SSLContext | None:
    """Create an SSL context for wss:// targets.

    Returns None for ws:// targets.
    """
    if urlparse(uri).scheme != "wss":
        return None
    if override is not None:
        return override
    if opts and opts.insecure:
        return make_insecure_ssl_context()
    try:
        return ssl.create_default_context(cafile=opts.ca_file if opts else None)
    except OSError as exc:
        raise TransportConfigError(f"TLS configuration error: {exc}") from exc


def _extra_headers(opts: ConnectOpts | None = None) -> dict[str, str] | None:
    if not opts:
        return None
    extra_headers = dict(opts.headers)
    if opts.origin:
        extra_headers["Origin"] = opts.origin
    return extra_headers or None


async def open_connection(
    uri: str,
    timeout: float,
    opts: ConnectOpts | None = None,
    ssl_context: ssl.SSLContext | None = None,
) -> websockets.ClientConnection:
    validate_ws_uri(uri)
    validate_connect_opts(opts)
    return await websockets.connect(
        uri,
        open_timeout=timeout,
        close_timeout=timeout,
        additional_headers=_extra_headers(opts),
        ssl=make_ssl_context(uri, opts, ssl_context),
    )


async def send_payload(
    uri: str,
    payload: bytes,
    mode: str,
    timeout: float,
    opts: ConnectOpts | None = None,
) -> TransportResult:
    start = time.monotonic()

    def _elapsed() -> float:
        return (time.monotonic() - start) * 1000

    try:
        async with asyncio.timeout(timeout):
            async with await open_connection(uri, timeout, opts) as ws:
                if mode == "text":
                    await ws.send(payload.decode(errors="replace"))
                else:
                    await ws.send(payload)

                try:
                    resp = await ws.recv()
                    if isinstance(resp, str):
                        resp = resp.encode()
                    return TransportResult(response=resp, duration_ms=_elapsed())
                except websockets.ConnectionClosed as e:
                    return handle_close(e, _elapsed())

    except websockets.ConnectionClosed as e:
        return handle_close(e, _elapsed())
    except Exception as e:
        return classify_error(e, _elapsed())


async def check_origin(uri: str, origin: str, timeout: float = 5.0) -> TransportResult:
    """Test if the server accepts a connection with the given Origin header.

    Used for Cross-Site WebSocket Hijacking (CSWSH) detection.
    If the server accepts the connection, it may be vulnerable.
    """
    return await send_payload(uri, b"", "binary", timeout, ConnectOpts(origin=origin))
