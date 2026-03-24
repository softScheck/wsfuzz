"""Tests for the HTTP-to-WebSocket harness."""

import asyncio
import http.client

from wsfuzz.harness import _handle_request


def _http_post(
    port: int, body: bytes, host: str = "127.0.0.1"
) -> http.client.HTTPResponse:
    """Send a POST request and return the response."""
    conn = http.client.HTTPConnection(host, port, timeout=5)
    conn.request("POST", "/", body=body)
    return conn.getresponse()


def _get_free_port() -> int:
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestHarnessEcho:
    """Harness against the echo server — payload goes through, response comes back."""

    def test_post_body_echoed(self, echo_server):
        port = _get_free_port()
        loop = asyncio.new_event_loop()

        async def _run():
            server = await asyncio.start_server(
                lambda r, w: _handle_request(
                    r,
                    w,
                    target=echo_server,
                    mode="text",
                    timeout=5.0,
                    opts=None,
                    template=None,
                ),
                "127.0.0.1",
                port,
            )
            async with server:
                resp = await loop.run_in_executor(
                    None, _http_post, port, b"hello from harness"
                )
                body = resp.read()
                assert resp.status == 200
                assert body == b"hello from harness"

        loop.run_until_complete(_run())
        loop.close()

    def test_binary_mode(self, echo_server):
        port = _get_free_port()
        loop = asyncio.new_event_loop()
        payload = b"\x00\x01\x02\xff"

        async def _run():
            server = await asyncio.start_server(
                lambda r, w: _handle_request(
                    r,
                    w,
                    target=echo_server,
                    mode="binary",
                    timeout=5.0,
                    opts=None,
                    template=None,
                ),
                "127.0.0.1",
                port,
            )
            async with server:
                resp = await loop.run_in_executor(None, _http_post, port, payload)
                body = resp.read()
                assert resp.status == 200
                assert body == payload

        loop.run_until_complete(_run())
        loop.close()

    def test_template_substitution(self, echo_server):
        port = _get_free_port()
        loop = asyncio.new_event_loop()

        async def _run():
            server = await asyncio.start_server(
                lambda r, w: _handle_request(
                    r,
                    w,
                    target=echo_server,
                    mode="text",
                    timeout=5.0,
                    opts=None,
                    template='{"user": "[FUZZ]"}',
                ),
                "127.0.0.1",
                port,
            )
            async with server:
                resp = await loop.run_in_executor(None, _http_post, port, b"admin")
                body = resp.read()
                assert resp.status == 200
                assert body == b'{"user": "admin"}'

        loop.run_until_complete(_run())
        loop.close()


class TestHarnessErrors:
    """Harness returns WS errors as HTTP 502 with details."""

    def test_error_server_returns_502(self, echo_server):
        port = _get_free_port()
        loop = asyncio.new_event_loop()

        async def _run():
            server = await asyncio.start_server(
                lambda r, w: _handle_request(
                    r,
                    w,
                    target=echo_server + "/error",
                    mode="text",
                    timeout=5.0,
                    opts=None,
                    template=None,
                ),
                "127.0.0.1",
                port,
            )
            async with server:
                resp = await loop.run_in_executor(None, _http_post, port, b"test")
                body = resp.read()
                assert resp.status == 502
                assert b"WS_ERROR" in body
                assert resp.getheader("X-WS-Error-Type") is not None

        loop.run_until_complete(_run())
        loop.close()

    def test_connection_refused_returns_502(self):
        port = _get_free_port()
        loop = asyncio.new_event_loop()

        async def _run():
            server = await asyncio.start_server(
                lambda r, w: _handle_request(
                    r,
                    w,
                    target="ws://127.0.0.1:1/nope",
                    mode="text",
                    timeout=2.0,
                    opts=None,
                    template=None,
                ),
                "127.0.0.1",
                port,
            )
            async with server:
                resp = await loop.run_in_executor(None, _http_post, port, b"test")
                body = resp.read()
                assert resp.status == 502
                assert b"connection_refused" in body or b"refused" in body.lower()

        loop.run_until_complete(_run())
        loop.close()


class TestHarnessVulnServer:
    """Harness against vulnerable endpoints — verifies error propagation."""

    def test_json_parse_error(self, vuln_server):
        port = _get_free_port()
        loop = asyncio.new_event_loop()

        async def _run():
            server = await asyncio.start_server(
                lambda r, w: _handle_request(
                    r,
                    w,
                    target=vuln_server + "/json-parse",
                    mode="text",
                    timeout=5.0,
                    opts=None,
                    template=None,
                ),
                "127.0.0.1",
                port,
            )
            async with server:
                resp = await loop.run_in_executor(
                    None, _http_post, port, b"{invalid json"
                )
                body = resp.read()
                assert resp.status == 502
                assert b"close_1011" in body or "1011" in (
                    resp.getheader("X-WS-Close-Code") or ""
                )

        loop.run_until_complete(_run())
        loop.close()

    def test_valid_json_succeeds(self, vuln_server):
        port = _get_free_port()
        loop = asyncio.new_event_loop()

        async def _run():
            server = await asyncio.start_server(
                lambda r, w: _handle_request(
                    r,
                    w,
                    target=vuln_server + "/json-parse",
                    mode="text",
                    timeout=5.0,
                    opts=None,
                    template=None,
                ),
                "127.0.0.1",
                port,
            )
            async with server:
                resp = await loop.run_in_executor(
                    None, _http_post, port, b'{"key": "value"}'
                )
                body = resp.read()
                assert resp.status == 200
                assert b"ok" in body

        loop.run_until_complete(_run())
        loop.close()

    def test_template_sqli_payload(self, vuln_server):
        """Simulate what SQLMap would do: inject into a template field."""
        port = _get_free_port()
        loop = asyncio.new_event_loop()

        async def _run():
            server = await asyncio.start_server(
                lambda r, w: _handle_request(
                    r,
                    w,
                    target=vuln_server + "/json-parse",
                    mode="text",
                    timeout=5.0,
                    opts=None,
                    template='{"id": "[FUZZ]"}',
                ),
                "127.0.0.1",
                port,
            )
            async with server:
                # Valid JSON after substitution, but server returns it fine
                resp = await loop.run_in_executor(None, _http_post, port, b"1")
                body = resp.read()
                assert resp.status == 200
                assert b"ok" in body

        loop.run_until_complete(_run())
        loop.close()
