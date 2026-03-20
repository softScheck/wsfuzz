import asyncio
import time
from dataclasses import dataclass, field

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


@dataclass
class ConnectOpts:
    """Extra options for WebSocket connections."""

    headers: dict[str, str] = field(default_factory=dict)
    origin: str | None = None


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

    def _error(msg: str, etype: str, *, refused: bool = False) -> TransportResult:
        return TransportResult(
            error=msg,
            error_type=etype,
            duration_ms=_elapsed(),
            connection_refused=refused,
        )

    extra_headers = {}
    if opts:
        extra_headers.update(opts.headers)
        if opts.origin:
            extra_headers["Origin"] = opts.origin

    try:
        async with asyncio.timeout(timeout):
            async with websockets.connect(
                uri,
                open_timeout=timeout,
                close_timeout=timeout,
                additional_headers=extra_headers or None,
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
    except ConnectionRefusedError:
        return _error("connection refused", "connection_refused", refused=True)
    except ConnectionResetError:
        return _error("connection reset by server", "connection_reset")
    except TimeoutError:
        return _error("timeout", "timeout")
    except OSError as e:
        err_str = str(e)
        is_refused = "Connect call failed" in err_str or "Connection refused" in err_str
        return _error(
            err_str,
            "connection_refused" if is_refused else "OSError",
            refused=is_refused,
        )
    except Exception as e:
        return _error(str(e), type(e).__name__)


async def check_origin(uri: str, origin: str, timeout: float = 5.0) -> TransportResult:
    """Test if the server accepts a connection with the given Origin header.

    Used for Cross-Site WebSocket Hijacking (CSWSH) detection.
    If the server accepts the connection, it may be vulnerable.
    """
    return await send_payload(uri, b"", "binary", timeout, ConnectOpts(origin=origin))
