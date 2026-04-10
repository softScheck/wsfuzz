import asyncio
import contextlib
import ssl
import subprocess
import threading
from collections.abc import Callable, Coroutine, Generator
from dataclasses import dataclass
from pathlib import Path

import pytest
import websockets

from tests.echo_server import start_server
from tests.vulnerable_server import start_vulnerable_server

type ServerStarter = Callable[[str, int], Coroutine[object, object, websockets.Server]]


@dataclass
class TlsEchoServer:
    uri: str
    client_context: ssl.SSLContext
    cert_path: Path


def _create_tls_material(tmp_dir: Path) -> tuple[Path, Path]:
    cert_path = tmp_dir / "cert.pem"
    key_path = tmp_dir / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return cert_path, key_path


async def _shutdown(server: websockets.Server) -> None:
    """Cleanly shut down the server and drain all pending tasks."""
    server.close()
    # Cancel all tasks (connection handlers, _close coroutines) before waiting
    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    for t in tasks:
        t.cancel()
    await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=1)


def _make_server_fixture(starter: ServerStarter) -> Callable[..., Generator[str]]:
    """Create a fixture that runs a WebSocket server in a background thread."""

    @pytest.fixture
    def fixture() -> Generator[str]:
        loop = asyncio.new_event_loop()
        server = loop.run_until_complete(starter("127.0.0.1", 0))
        port = server.sockets[0].getsockname()[1]
        uri = f"ws://127.0.0.1:{port}"

        thread = threading.Thread(target=loop.run_forever, daemon=True)
        thread.start()

        yield uri

        future = asyncio.run_coroutine_threadsafe(_shutdown(server), loop)
        with contextlib.suppress(Exception):
            future.result(timeout=5)
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=2)
        loop.close()

    return fixture


echo_server = _make_server_fixture(start_server)
vuln_server = _make_server_fixture(start_vulnerable_server)


@pytest.fixture
def tls_echo_server(tmp_path_factory) -> Generator[TlsEchoServer]:
    tls_dir = tmp_path_factory.mktemp("tls")
    cert_path, key_path = _create_tls_material(tls_dir)

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certfile=cert_path, keyfile=key_path)

    client_context = ssl.create_default_context(cafile=str(cert_path))

    loop = asyncio.new_event_loop()
    server = loop.run_until_complete(
        start_server("127.0.0.1", 0, ssl_context=server_context)
    )
    port = server.sockets[0].getsockname()[1]

    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()

    yield TlsEchoServer(
        uri=f"wss://127.0.0.1:{port}",
        client_context=client_context,
        cert_path=cert_path,
    )

    future = asyncio.run_coroutine_threadsafe(_shutdown(server), loop)
    with contextlib.suppress(Exception):
        future.result(timeout=5)
    loop.call_soon_threadsafe(loop.stop)
    thread.join(timeout=2)
    loop.close()
