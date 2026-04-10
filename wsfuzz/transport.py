import asyncio
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import websockets


@dataclass
class TransportResult:
    response: bytes | None = None
    error: str | None = None
    error_type: str | None = None
    close_code: int | None = None
    duration_ms: float = 0.0
    connection_refused: bool = False


def _handle_close(e: websockets.ConnectionClosed, elapsed_ms: float) -> TransportResult:
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


def classify_error(e: Exception, elapsed_ms: float) -> TransportResult:
    """Classify a network exception into a TransportResult.

    Shared by both normal (websockets) and raw (TCP) transport so that
    error classification stays consistent across modes.
    """
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
        is_refused = "Connect call failed" in err_str or "Connection refused" in err_str
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
    return ConnectOpts(
        headers=dict(headers or {}),
        origin=origin,
        ca_file=ca_file,
        insecure=insecure,
    )


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
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=opts.ca_file if opts else None)


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

    extra_headers = {}
    if opts:
        extra_headers.update(opts.headers)
        if opts.origin:
            extra_headers["Origin"] = opts.origin

    try:
        ssl_context = make_ssl_context(uri, opts)
        async with asyncio.timeout(timeout):
            async with websockets.connect(
                uri,
                open_timeout=timeout,
                close_timeout=timeout,
                additional_headers=extra_headers or None,
                ssl=ssl_context,
            ) as ws:
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
                    return _handle_close(e, _elapsed())

    except websockets.ConnectionClosed as e:
        return _handle_close(e, _elapsed())
    except Exception as e:
        return classify_error(e, _elapsed())


async def check_origin(uri: str, origin: str, timeout: float = 5.0) -> TransportResult:
    """Test if the server accepts a connection with the given Origin header.

    Used for Cross-Site WebSocket Hijacking (CSWSH) detection.
    If the server accepts the connection, it may be vulnerable.
    """
    return await send_payload(uri, b"", "binary", timeout, ConnectOpts(origin=origin))
