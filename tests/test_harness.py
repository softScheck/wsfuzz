"""Tests for the HTTP-to-WebSocket harness."""

import asyncio
import http.client
import json
import socket
from http import HTTPStatus
from typing import cast

import wsfuzz.harness as harness
from wsfuzz.harness import _handle_request, _send_response


def _http_post(
    port: int, body: bytes, host: str = "127.0.0.1"
) -> http.client.HTTPResponse:
    """Send a POST request and return the response."""
    conn = http.client.HTTPConnection(host, port, timeout=5)
    conn.request("POST", "/", body=body)
    return conn.getresponse()


def _get_free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _raw_http_request(port: int, request: bytes) -> tuple[bytes, bytes]:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(request)
        sock.shutdown(socket.SHUT_WR)
        response = bytearray()
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
    head, _, body = bytes(response).partition(b"\r\n\r\n")
    return head, body


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

    def test_empty_payload_returns_200_with_empty_body(self, echo_server):
        port = _get_free_port()
        loop = asyncio.new_event_loop()

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
                resp = await loop.run_in_executor(None, _http_post, port, b"")
                body = resp.read()
                assert resp.status == 200
                assert body == b""

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

    def test_binary_template_preserves_raw_fuzz_bytes(self, echo_server):
        port = _get_free_port()
        loop = asyncio.new_event_loop()
        payload = b"\xff\x00\x80A"

        async def _run():
            server = await asyncio.start_server(
                lambda r, w: _handle_request(
                    r,
                    w,
                    target=echo_server,
                    mode="binary",
                    timeout=5.0,
                    opts=None,
                    template="[FUZZ]",
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

    def test_binary_template_rejects_non_utf8_interpolation(self, echo_server):
        port = _get_free_port()
        loop = asyncio.new_event_loop()

        async def _run():
            server = await asyncio.start_server(
                lambda r, w: _handle_request(
                    r,
                    w,
                    target=echo_server,
                    mode="binary",
                    timeout=5.0,
                    opts=None,
                    template='{"user":"[FUZZ]"}',
                ),
                "127.0.0.1",
                port,
            )
            async with server:
                resp = await loop.run_in_executor(None, _http_post, port, b"\xff")
                body = resp.read()
                assert resp.status == 400
                assert (
                    body
                    == b"binary [FUZZ] payload cannot be interpolated inside a text template"
                )

        loop.run_until_complete(_run())
        loop.close()

    def test_template_substitution_with_header_and_query_markers(self, echo_server):
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
                    template='{"user":"[FUZZ]","tenant":"[QUERY:tenant]","token":"[HEADER:X-Token]"}',
                ),
                "127.0.0.1",
                port,
            )
            async with server:
                request = (
                    b"POST /?tenant=acme HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"X-Token: secret\r\n"
                    b"Content-Length: 5\r\n\r\n"
                    b"admin"
                )
                head, body = await loop.run_in_executor(
                    None, _raw_http_request, port, request
                )
                assert b"200 OK" in head
                assert body == b'{"user":"admin","tenant":"acme","token":"secret"}'

        loop.run_until_complete(_run())
        loop.close()

    def test_template_does_not_reinterpret_marker_text_inside_body(self, echo_server):
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
                    template='{"payload":"[FUZZ]","method":"[METHOD]"}',
                ),
                "127.0.0.1",
                port,
            )
            async with server:
                body = b"[METHOD] [QUERY:x] [HEADER:Y]"
                resp = await loop.run_in_executor(None, _http_post, port, body)
                echoed = resp.read()
                assert resp.status == 200
                assert (
                    echoed
                    == b'{"payload":"[METHOD] [QUERY:x] [HEADER:Y]","method":"POST"}'
                )

        loop.run_until_complete(_run())
        loop.close()

    def test_template_substitution_with_path_method_and_repeated_markers(
        self, echo_server
    ):
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
                    template='{"method":"[METHOD]","path":"[PATH]","header":"[HEADER:X-Token]","headers":"[HEADERS:X-Token]","query":"[QUERY:tenant]","queries":"[QUERIES:tenant]"}',
                ),
                "127.0.0.1",
                port,
            )
            async with server:
                request = (
                    b"POST /bridge?tenant=acme&tenant=beta HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"X-Token: first\r\n"
                    b"X-Token: second\r\n"
                    b"Content-Length: 4\r\n\r\n"
                    b"body"
                )
                head, body = await loop.run_in_executor(
                    None, _raw_http_request, port, request
                )
                assert b"200 OK" in head
                assert (
                    body
                    == b'{"method":"POST","path":"/bridge","header":"first","headers":"first,second","query":"acme","queries":"acme,beta"}'
                )

        loop.run_until_complete(_run())
        loop.close()

    def test_chunked_request_body(self, echo_server):
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
                request = (
                    b"POST / HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"Transfer-Encoding: chunked\r\n\r\n"
                    b"5\r\nhello\r\n"
                    b"6\r\n world\r\n"
                    b"0\r\n\r\n"
                )
                head, body = await loop.run_in_executor(
                    None, _raw_http_request, port, request
                )
                assert b"200 OK" in head
                assert body == b"hello world"

        loop.run_until_complete(_run())
        loop.close()

    def test_json_template_escapes_fuzz_payload(self, echo_server):
        port = _get_free_port()
        loop = asyncio.new_event_loop()
        payload = b'quote" slash\\ newline\n tab\t'

        async def _run():
            server = await asyncio.start_server(
                lambda r, w: _handle_request(
                    r,
                    w,
                    target=echo_server,
                    mode="text",
                    timeout=5.0,
                    opts=None,
                    template='{"payload":"[FUZZ]"}',
                    template_format="json",
                ),
                "127.0.0.1",
                port,
            )
            async with server:
                resp = await loop.run_in_executor(None, _http_post, port, payload)
                body = resp.read()
                assert resp.status == 200
                assert json.loads(body.decode()) == {"payload": payload.decode()}

        loop.run_until_complete(_run())
        loop.close()

    def test_json_template_escapes_header_and_query_markers(self, echo_server):
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
                    template='{"tenant":"[QUERY:tenant]","token":"[HEADER:X-Token]","combined":"prefix-[FUZZ]"}',
                    template_format="json",
                ),
                "127.0.0.1",
                port,
            )
            async with server:
                request = (
                    b"POST /?tenant=a%22b HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"X-Token: t\\value\r\n"
                    b"Content-Length: 4\r\n\r\n"
                    b"body"
                )
                head, body = await loop.run_in_executor(
                    None, _raw_http_request, port, request
                )
                assert b"200 OK" in head
                assert json.loads(body.decode()) == {
                    "tenant": 'a"b',
                    "token": "t\\value",
                    "combined": "prefix-body",
                }

        loop.run_until_complete(_run())
        loop.close()

    def test_json_template_substitutes_object_keys(self, echo_server):
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
                    template='{"[QUERY:key]":"[FUZZ]"}',
                    template_format="json",
                ),
                "127.0.0.1",
                port,
            )
            async with server:
                request = (
                    b"POST /?key=field%22name HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"Content-Length: 5\r\n\r\n"
                    b"value"
                )
                head, body = await loop.run_in_executor(
                    None, _raw_http_request, port, request
                )
                assert b"200 OK" in head
                assert json.loads(body.decode()) == {'field"name': "value"}

        loop.run_until_complete(_run())
        loop.close()

    def test_invalid_json_template_returns_400(self, echo_server):
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
                    template='{"payload":"[FUZZ]"',
                    template_format="json",
                ),
                "127.0.0.1",
                port,
            )
            async with server:
                resp = await loop.run_in_executor(None, _http_post, port, b"body")
                body = resp.read()
                assert resp.status == 400
                assert body == b"JSON harness template is not valid JSON"

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

    def test_invalid_request_returns_400(self, echo_server):
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
                request = b"BROKEN\r\n\r\n"
                head, body = await loop.run_in_executor(
                    None, _raw_http_request, port, request
                )
                assert b"400 Bad Request" in head
                assert body == b"Bad Request"

        loop.run_until_complete(_run())
        loop.close()

    def test_malformed_http_version_returns_400(self, echo_server):
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
                request = (
                    b"POST / HTTP/banana\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                head, body = await loop.run_in_executor(
                    None, _raw_http_request, port, request
                )
                assert b"400 Bad Request" in head
                assert body == b"Bad Request"

        loop.run_until_complete(_run())
        loop.close()

    def test_malformed_request_target_returns_400(self, echo_server):
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
                request = (
                    b"POST http://[::1 HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                head, body = await loop.run_in_executor(
                    None, _raw_http_request, port, request
                )
                assert b"400 Bad Request" in head
                assert body == b"Bad Request"

        loop.run_until_complete(_run())
        loop.close()

    def test_oversized_header_line_returns_400(self, echo_server):
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
                request = (
                    b"POST / HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    + b"X-Long: "
                    + (b"a" * 70000)
                    + b"\r\nContent-Length: 0\r\n\r\n"
                )
                head, body = await loop.run_in_executor(
                    None, _raw_http_request, port, request
                )
                assert b"400 Bad Request" in head
                assert body == b"Bad Request"

        loop.run_until_complete(_run())
        loop.close()

    def test_empty_header_name_returns_400(self, echo_server):
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
                request = (
                    b"POST / HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b": broken\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                head, body = await loop.run_in_executor(
                    None, _raw_http_request, port, request
                )
                assert b"400 Bad Request" in head
                assert body == b"Bad Request"

        loop.run_until_complete(_run())
        loop.close()

    def test_invalid_header_name_returns_400(self, echo_server):
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
                request = (
                    b"POST / HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"Bad Header: broken\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                head, body = await loop.run_in_executor(
                    None, _raw_http_request, port, request
                )
                assert b"400 Bad Request" in head
                assert body == b"Bad Request"

        loop.run_until_complete(_run())
        loop.close()

    def test_header_name_whitespace_before_colon_returns_400(self, echo_server):
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
                request = (
                    b"POST / HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"X-Test : broken\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                head, body = await loop.run_in_executor(
                    None, _raw_http_request, port, request
                )
                assert b"400 Bad Request" in head
                assert body == b"Bad Request"

        loop.run_until_complete(_run())
        loop.close()

    def test_header_value_control_character_returns_400(self, echo_server):
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
                request = (
                    b"POST / HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"X-Test: ok\x0bbad\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                head, body = await loop.run_in_executor(
                    None, _raw_http_request, port, request
                )
                assert b"400 Bad Request" in head
                assert body == b"Bad Request"

        loop.run_until_complete(_run())
        loop.close()

    def test_conflicting_content_length_returns_400(self, echo_server):
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
                request = (
                    b"POST / HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"Content-Length: 4\r\n"
                    b"Content-Length: 5\r\n\r\n"
                    b"hello"
                )
                head, body = await loop.run_in_executor(
                    None, _raw_http_request, port, request
                )
                assert b"400 Bad Request" in head
                assert body == b"Bad Request"

        loop.run_until_complete(_run())
        loop.close()

    def test_non_digit_content_length_returns_400(self, echo_server):
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
                request = (
                    b"POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: +0\r\n\r\n"
                )
                head, body = await loop.run_in_executor(
                    None, _raw_http_request, port, request
                )
                assert b"400 Bad Request" in head
                assert body == b"Bad Request"

        loop.run_until_complete(_run())
        loop.close()

    def test_oversized_content_length_returns_413(self, echo_server, monkeypatch):
        monkeypatch.setattr(harness, "_MAX_HARNESS_BODY_BYTES", 4)
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
                request = (
                    b"POST / HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"Content-Length: 5\r\n\r\n"
                    b"hello"
                )
                head, body = await loop.run_in_executor(
                    None, _raw_http_request, port, request
                )
                expected = HTTPStatus.REQUEST_ENTITY_TOO_LARGE.phrase.encode()
                assert b"413 " + expected in head
                assert body == expected

        loop.run_until_complete(_run())
        loop.close()

    def test_oversized_chunked_body_returns_413(self, echo_server, monkeypatch):
        monkeypatch.setattr(harness, "_MAX_HARNESS_BODY_BYTES", 4)
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
                request = (
                    b"POST / HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"Transfer-Encoding: chunked\r\n\r\n"
                    b"5\r\nhello\r\n"
                    b"0\r\n\r\n"
                )
                head, body = await loop.run_in_executor(
                    None, _raw_http_request, port, request
                )
                expected = HTTPStatus.REQUEST_ENTITY_TOO_LARGE.phrase.encode()
                assert b"413 " + expected in head
                assert body == expected

        loop.run_until_complete(_run())
        loop.close()

    def test_send_response_ignores_disconnected_client(self):
        class ClosedWriter:
            def write(self, data: bytes) -> None:
                raise ConnectionResetError("client closed")

            async def drain(self) -> None:
                raise AssertionError("drain should not run after write failure")

            def close(self) -> None:
                return None

            async def wait_closed(self) -> None:
                raise ConnectionResetError("already closed")

        asyncio.run(
            _send_response(
                cast(asyncio.StreamWriter, ClosedWriter()),
                HTTPStatus.OK,
                b"ignored",
            )
        )

    def test_get_returns_405(self, echo_server):
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
                request = (
                    b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n"
                )
                head, body = await loop.run_in_executor(
                    None, _raw_http_request, port, request
                )
                assert b"405 Method Not Allowed" in head
                assert b"Allow: POST" in head
                assert body == b"Method Not Allowed"

        loop.run_until_complete(_run())
        loop.close()

    def test_missing_content_length_returns_411(self, echo_server):
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
                request = b"POST / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
                head, body = await loop.run_in_executor(
                    None, _raw_http_request, port, request
                )
                assert b"411 Length Required" in head
                assert body == b"Length Required"

        loop.run_until_complete(_run())
        loop.close()

    def test_unknown_transfer_encoding_returns_501(self, echo_server):
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
                request = (
                    b"POST / HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"Transfer-Encoding: gzip\r\n\r\n"
                )
                head, body = await loop.run_in_executor(
                    None, _raw_http_request, port, request
                )
                assert b"501 Not Implemented" in head
                assert body == b"Not Implemented"

        loop.run_until_complete(_run())
        loop.close()

    def test_transfer_encoding_token_matching_is_strict(self, echo_server):
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
                request = (
                    b"POST / HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"Transfer-Encoding: notchunked\r\n\r\n"
                )
                head, body = await loop.run_in_executor(
                    None, _raw_http_request, port, request
                )
                assert b"501 Not Implemented" in head
                assert body == b"Not Implemented"

        loop.run_until_complete(_run())
        loop.close()

    def test_combined_transfer_encoding_returns_501(self, echo_server):
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
                request = (
                    b"POST / HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"Transfer-Encoding: gzip, chunked\r\n\r\n"
                    b"0\r\n\r\n"
                )
                head, body = await loop.run_in_executor(
                    None, _raw_http_request, port, request
                )
                assert b"501 Not Implemented" in head
                assert body == b"Not Implemented"

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
