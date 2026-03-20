import asyncio
import contextlib
import threading
from collections.abc import Callable, Coroutine, Generator

import pytest
import websockets

from tests.echo_server import start_server
from tests.vulnerable_server import start_vulnerable_server

type ServerStarter = Callable[[str, int], Coroutine[object, object, websockets.Server]]


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
