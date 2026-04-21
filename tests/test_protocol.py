"""WebSocket protocol-level security tests.

Tests that the fuzzer can send non-conforming WebSocket frames and detect
protocol violations. Uses raw TCP to bypass the websockets library's
protocol enforcement.

RFC 6455 violations tested:
- Reserved opcodes (3-7, 0xB-0xF)
- Unmasked client frames
- RSV bits set without negotiated extension
- Control frames with payload > 125 bytes
- Fragmented control frames (FIN=0 on control opcode)
- Invalid UTF-8 in text frames
- Data after close frame
- Payload length mismatch (declared vs actual)
- Handshake header fuzzing
- CSWSH (Origin validation)
"""

import asyncio
import base64
import hashlib
import struct

import pytest

from wsfuzz.raw import (
    OP_BINARY,
    OP_CLOSE,
    OP_CONTINUATION,
    OP_PING,
    OP_TEXT,
    _build_handshake,
    _parse_close_frame,
    build_frame,
    send_raw,
)
from wsfuzz.transport import ConnectOpts, TransportResult, check_origin


class TestBuildFrame:
    def test_basic_masked_frame(self):
        frame = build_frame(b"hello", opcode=OP_TEXT, mask=True)
        # First byte: FIN=1, opcode=1 -> 0x81
        assert frame[0] == 0x81
        # Second byte: MASK=1, len=5 -> 0x85
        assert frame[1] == 0x85
        # 2 header + 4 mask key + 5 payload = 11 bytes
        assert len(frame) == 11

    def test_unmasked_frame(self):
        frame = build_frame(b"hello", opcode=OP_TEXT, mask=False)
        assert frame[0] == 0x81
        # MASK=0, len=5 -> 0x05
        assert frame[1] == 0x05
        # 2 header + 5 payload = 7 bytes (no mask key)
        assert len(frame) == 7

    def test_reserved_opcode(self):
        frame = build_frame(b"test", opcode=0x03)
        # FIN=1, opcode=3 -> 0x83
        assert frame[0] == 0x83

    def test_rsv_bits(self):
        frame = build_frame(b"x", opcode=OP_BINARY, rsv1=True, rsv2=True, rsv3=True)
        # FIN=1, RSV1=1, RSV2=1, RSV3=1, opcode=2 -> 0xF2
        assert frame[0] == 0xF2

    def test_fin_unset(self):
        frame = build_frame(b"fragment", opcode=OP_TEXT, fin=False)
        # FIN=0, opcode=1 -> 0x01
        assert frame[0] == 0x01

    def test_extended_16bit_length(self):
        payload = b"A" * 200
        frame = build_frame(payload, mask=False)
        assert frame[1] == 126  # 16-bit extended length
        length = struct.unpack("!H", frame[2:4])[0]
        assert length == 200

    def test_extended_64bit_length(self):
        payload = b"A" * 70000
        frame = build_frame(payload, mask=False)
        assert frame[1] == 127  # 64-bit extended length
        length = struct.unpack("!Q", frame[2:10])[0]
        assert length == 70000

    def test_empty_payload(self):
        frame = build_frame(b"", opcode=OP_PING, mask=True)
        assert frame[0] == 0x89  # FIN + PING
        assert frame[1] == 0x80  # MASK + len=0

    @pytest.mark.parametrize("fake_length", [-1, 2**64])
    def test_rejects_unencodable_fake_length(self, fake_length):
        with pytest.raises(
            ValueError,
            match="frame length must be between 0 and 2\\^64-1",
        ):
            build_frame(b"x", opcode=OP_TEXT, fake_length=fake_length)


class TestParseCloseFrame:
    def test_close_1002(self):
        """Close frame with code 1002 (protocol error) should be detected."""
        frame = build_frame(
            struct.pack("!H", 1002) + b"protocol error", opcode=OP_CLOSE, mask=False
        )
        result = _parse_close_frame(frame)
        assert result is not None
        assert result.close_code == 1002
        assert result.error_type == "close_1002"

    def test_close_1000_not_interesting(self):
        """Close code 1000 (normal) should not be flagged."""
        frame = build_frame(
            struct.pack("!H", 1000) + b"normal", opcode=OP_CLOSE, mask=False
        )
        result = _parse_close_frame(frame)
        assert result is None

    def test_non_close_frame(self):
        """Non-close frames should return None."""
        frame = build_frame(b"hello", opcode=OP_TEXT, mask=False)
        assert _parse_close_frame(frame) is None

    def test_close_1011(self):
        frame = build_frame(
            struct.pack("!H", 1011) + b"internal", opcode=OP_CLOSE, mask=False
        )
        result = _parse_close_frame(frame)
        assert result is not None
        assert result.close_code == 1011

    def test_too_short(self):
        assert _parse_close_frame(b"\x88") is None
        assert _parse_close_frame(b"") is None

    def test_elapsed_ms_propagated(self):
        frame = build_frame(
            struct.pack("!H", 1002) + b"error", opcode=OP_CLOSE, mask=False
        )
        result = _parse_close_frame(frame, elapsed_ms=42.5)
        assert result is not None
        assert result.duration_ms == 42.5

    def test_elapsed_ms_defaults_to_zero(self):
        frame = build_frame(
            struct.pack("!H", 1003) + b"error", opcode=OP_CLOSE, mask=False
        )
        result = _parse_close_frame(frame)
        assert result is not None
        assert result.duration_ms == 0.0


class TestProtocolViolations:
    """Send protocol-violating frames to the echo server.

    The websockets library server should reject these with close code 1002
    (protocol error) or 1003 (unsupported data), or drop the connection.
    The fuzzer should detect these as interesting errors.
    """

    def test_reserved_opcode_rejected(self, echo_server):
        """RFC 6455 5.2: opcodes 3-7 and 0xB-0xF are reserved."""
        frame = build_frame(b"test", opcode=0x03, mask=True)
        result = asyncio.run(send_raw(echo_server, frame, 5.0))
        assert result.error is not None

    def test_all_reserved_opcodes(self, echo_server):
        """All reserved opcodes must be rejected by the server."""
        reserved = [3, 4, 5, 6, 7, 0xB, 0xC, 0xD, 0xE, 0xF]
        for opcode in reserved:
            frame = build_frame(b"x", opcode=opcode, mask=True)
            result = asyncio.run(send_raw(echo_server, frame, 2.0))
            assert result.error is not None, f"opcode {opcode:#x} was not rejected"

    def test_unmasked_client_frame_rejected(self, echo_server):
        """RFC 6455 5.1: client frames MUST be masked."""
        frame = build_frame(b"hello", opcode=OP_TEXT, mask=False)
        result = asyncio.run(send_raw(echo_server, frame, 5.0))
        assert result.error is not None

    def test_rsv_bits_without_extension(self, echo_server):
        """RFC 6455 5.2: RSV bits must be 0 unless extension is negotiated."""
        frame = build_frame(b"test", opcode=OP_TEXT, mask=True, rsv1=True)
        result = asyncio.run(send_raw(echo_server, frame, 5.0))
        assert result.error is not None

    def test_oversized_control_frame(self, echo_server):
        """RFC 6455 5.5: control frames MUST have payload <= 125 bytes."""
        payload = b"A" * 200
        frame = build_frame(payload, opcode=OP_PING, mask=True)
        result = asyncio.run(send_raw(echo_server, frame, 5.0))
        assert result.error is not None

    def test_fragmented_control_frame(self, echo_server):
        """RFC 6455 5.5: control frames MUST NOT be fragmented."""
        frame = build_frame(b"ping", opcode=OP_PING, fin=False, mask=True)
        result = asyncio.run(send_raw(echo_server, frame, 5.0))
        assert result.error is not None

    def test_continuation_without_start(self, echo_server):
        """RFC 6455 5.4: continuation frame without initial frame."""
        frame = build_frame(b"orphan", opcode=OP_CONTINUATION, mask=True)
        result = asyncio.run(send_raw(echo_server, frame, 5.0))
        assert result.error is not None

    def test_invalid_utf8_in_text_frame(self, echo_server):
        """RFC 6455 5.6: text frames must contain valid UTF-8."""
        payload = b"\xff\xfe\x80\x81invalid"
        frame = build_frame(payload, opcode=OP_TEXT, mask=True)
        result = asyncio.run(send_raw(echo_server, frame, 5.0))
        assert result.error is not None

    def test_close_frame_invalid_code(self, echo_server):
        """RFC 6455 7.4.1: close codes 0-999 are not used."""
        payload = struct.pack("!H", 999) + b"bad code"
        frame = build_frame(payload, opcode=OP_CLOSE, mask=True)
        result = asyncio.run(send_raw(echo_server, frame, 5.0))
        assert result.error is not None

    def test_close_frame_reserved_code(self, echo_server):
        """RFC 6455 7.4.1: codes 1004, 1005, 1006 are reserved."""
        for code in [1004, 1005, 1006]:
            payload = struct.pack("!H", code) + b"reserved"
            frame = build_frame(payload, opcode=OP_CLOSE, mask=True)
            result = asyncio.run(send_raw(echo_server, frame, 2.0))
            assert result.error is not None, f"close code {code} was not rejected"

    def test_zero_length_close_code(self, echo_server):
        """Close frame with 1 byte (invalid: must be 0 or >= 2 bytes)."""
        payload = b"\x03"  # 1 byte — not a valid close payload
        frame = build_frame(payload, opcode=OP_CLOSE, mask=True)
        result = asyncio.run(send_raw(echo_server, frame, 5.0))
        assert result.error is not None

    def test_valid_frame_still_works(self, echo_server):
        """Sanity check: a valid masked text frame echoes correctly."""
        frame = build_frame(b"hello", opcode=OP_TEXT, mask=True)
        result = asyncio.run(send_raw(echo_server, frame, 5.0))
        assert result.error is None
        # Raw mode returns full frame bytes — payload embedded after header
        assert b"hello" in result.response

    def test_valid_frame_still_works_over_wss(self, tls_echo_server):
        frame = build_frame(b"secure hello", opcode=OP_TEXT, mask=True)
        result = asyncio.run(
            send_raw(
                tls_echo_server.uri,
                frame,
                5.0,
                ConnectOpts(ca_file=str(tls_echo_server.cert_path)),
            )
        )
        assert result.error is None
        assert b"secure hello" in result.response

    def test_valid_frame_still_works_over_wss_insecure(self, tls_echo_server):
        frame = build_frame(b"secure hello", opcode=OP_TEXT, mask=True)
        result = asyncio.run(
            send_raw(
                tls_echo_server.uri,
                frame,
                5.0,
                ConnectOpts(insecure=True),
            )
        )
        assert result.error is None
        assert b"secure hello" in result.response

    def test_raw_handshake_preserves_path_params_and_query_string(self):
        captured: dict[str, bytes] = {}

        def accept_from_request(request: bytes) -> bytes:
            for line in request.split(b"\r\n"):
                if line.lower().startswith(b"sec-websocket-key:"):
                    key = line.split(b":", 1)[1].strip().decode()
                    digest = hashlib.sha1(
                        (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
                    ).digest()
                    return base64.b64encode(digest)
            raise AssertionError("missing Sec-WebSocket-Key")

        async def handler(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            captured["request"] = await reader.readuntil(b"\r\n\r\n")
            writer.write(
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n"
                b"Sec-WebSocket-Accept: "
                + accept_from_request(captured["request"])
                + b"\r\n\r\n"
            )
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        async def run_test() -> None:
            server = await asyncio.start_server(handler, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            async with server:
                frame = build_frame(b"hello", opcode=OP_TEXT, mask=True)
                result = await send_raw(
                    f"ws://127.0.0.1:{port}/echo;v=1?token=abc&mode=test",
                    frame,
                    2.0,
                )
                assert result is not None

        asyncio.run(run_test())
        assert b"GET /echo;v=1?token=abc&mode=test HTTP/1.1" in captured["request"]

    def test_raw_handshake_brackets_ipv6_host_header(self):
        request = _build_handshake("::1", 8080, "/echo", "key")

        assert "Host: [::1]:8080\r\n" in request

    def test_send_raw_rejects_non_websocket_uri(self):
        frame = build_frame(b"hello", opcode=OP_TEXT, mask=True)

        result = asyncio.run(send_raw("http://127.0.0.1:1/echo", frame, 1.0))

        assert result.error_type == "ValueError"
        assert result.error == "target must be a ws:// or wss:// URL"

    def test_raw_handshake_requires_status_101(self):
        async def handler(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(
                b"HTTP/1.1 201 Created\r\n"
                b"X-Debug: 101 but not switching protocols\r\n\r\n"
            )
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        async def run_test() -> TransportResult:
            server = await asyncio.start_server(handler, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            async with server:
                frame = build_frame(b"hello", opcode=OP_TEXT, mask=True)
                return await send_raw(f"ws://127.0.0.1:{port}/echo", frame, 2.0)

        result = asyncio.run(run_test())
        assert result.error_type == "handshake_failed"
        assert result.response is not None
        assert result.response.startswith(b"HTTP/1.1 201")

    def test_raw_handshake_rejects_non_http_status_line(self):
        async def handler(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            request = await reader.readuntil(b"\r\n\r\n")
            key = None
            for line in request.split(b"\r\n"):
                if line.lower().startswith(b"sec-websocket-key:"):
                    key = line.split(b":", 1)[1].strip().decode()
                    break
            assert key is not None
            digest = hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
            ).digest()
            accept = base64.b64encode(digest)
            writer.write(
                b"NOTHTTP 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n"
                b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n"
            )
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        async def run_test() -> TransportResult:
            server = await asyncio.start_server(handler, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            async with server:
                frame = build_frame(b"hello", opcode=OP_TEXT, mask=True)
                return await send_raw(f"ws://127.0.0.1:{port}/echo", frame, 2.0)

        result = asyncio.run(run_test())
        assert result.error_type == "handshake_failed"
        assert "malformed HTTP status line" in (result.error or "")

    @pytest.mark.parametrize("status_prefix", [b"HTTP/banana", b"HTTP/1"])
    def test_raw_handshake_rejects_malformed_http_version(self, status_prefix):
        async def handler(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            request = await reader.readuntil(b"\r\n\r\n")
            key = None
            for line in request.split(b"\r\n"):
                if line.lower().startswith(b"sec-websocket-key:"):
                    key = line.split(b":", 1)[1].strip().decode()
                    break
            assert key is not None
            digest = hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
            ).digest()
            accept = base64.b64encode(digest)
            writer.write(
                status_prefix + b" 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n"
                b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n"
            )
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        async def run_test() -> TransportResult:
            server = await asyncio.start_server(handler, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            async with server:
                frame = build_frame(b"hello", opcode=OP_TEXT, mask=True)
                return await send_raw(f"ws://127.0.0.1:{port}/echo", frame, 2.0)

        result = asyncio.run(run_test())
        assert result.error_type == "handshake_failed"
        assert "malformed HTTP status line" in (result.error or "")

    def test_raw_handshake_requires_upgrade_header(self):
        async def handler(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Connection: Upgrade\r\n"
                b"Sec-WebSocket-Accept: invalid\r\n\r\n"
            )
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        async def run_test() -> TransportResult:
            server = await asyncio.start_server(handler, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            async with server:
                frame = build_frame(b"hello", opcode=OP_TEXT, mask=True)
                return await send_raw(f"ws://127.0.0.1:{port}/echo", frame, 2.0)

        result = asyncio.run(run_test())
        assert result.error_type == "handshake_failed"
        assert "Upgrade" in (result.error or "")

    def test_raw_handshake_requires_valid_accept_header(self):
        async def handler(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n"
                b"Sec-WebSocket-Accept: invalid\r\n\r\n"
            )
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        async def run_test() -> TransportResult:
            server = await asyncio.start_server(handler, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            async with server:
                frame = build_frame(b"hello", opcode=OP_TEXT, mask=True)
                return await send_raw(f"ws://127.0.0.1:{port}/echo", frame, 2.0)

        result = asyncio.run(run_test())
        assert result.error_type == "handshake_failed"
        assert "Sec-WebSocket-Accept" in (result.error or "")

    def test_raw_handshake_rejects_malformed_required_header_name(self):
        async def handler(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            request = await reader.readuntil(b"\r\n\r\n")
            key = None
            for line in request.split(b"\r\n"):
                if line.lower().startswith(b"sec-websocket-key:"):
                    key = line.split(b":", 1)[1].strip().decode()
                    break
            assert key is not None
            digest = hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
            ).digest()
            accept = base64.b64encode(digest)
            writer.write(
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n"
                b"Sec-WebSocket-\xffAccept: " + accept + b"\r\n\r\n"
            )
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        async def run_test() -> TransportResult:
            server = await asyncio.start_server(handler, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            async with server:
                frame = build_frame(b"hello", opcode=OP_TEXT, mask=True)
                return await send_raw(f"ws://127.0.0.1:{port}/echo", frame, 2.0)

        result = asyncio.run(run_test())
        assert result.error_type == "handshake_failed"
        assert "Sec-WebSocket-Accept" in (result.error or "")

    def test_raw_handshake_rejects_malformed_required_header_value(self):
        async def handler(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            request = await reader.readuntil(b"\r\n\r\n")
            key = None
            for line in request.split(b"\r\n"):
                if line.lower().startswith(b"sec-websocket-key:"):
                    key = line.split(b":", 1)[1].strip().decode()
                    break
            assert key is not None
            digest = hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
            ).digest()
            accept = base64.b64encode(digest)
            writer.write(
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n"
                b"Sec-WebSocket-Accept: " + accept + b"\xff\r\n\r\n"
            )
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        async def run_test() -> TransportResult:
            server = await asyncio.start_server(handler, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            async with server:
                frame = build_frame(b"hello", opcode=OP_TEXT, mask=True)
                return await send_raw(f"ws://127.0.0.1:{port}/echo", frame, 2.0)

        result = asyncio.run(run_test())
        assert result.error_type == "handshake_failed"
        assert "Sec-WebSocket-Accept" in (result.error or "")

    def test_raw_handshake_accepts_repeated_connection_headers(self):
        async def handler(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            request = await reader.readuntil(b"\r\n\r\n")
            key = None
            for line in request.split(b"\r\n"):
                if line.lower().startswith(b"sec-websocket-key:"):
                    key = line.split(b":", 1)[1].strip().decode()
                    break
            assert key is not None
            digest = hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
            ).digest()
            accept = base64.b64encode(digest)
            writer.write(
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n"
                b"Connection: keep-alive\r\n"
                b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n"
            )
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        async def run_test() -> TransportResult:
            server = await asyncio.start_server(handler, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            async with server:
                frame = build_frame(b"hello", opcode=OP_TEXT, mask=True)
                return await send_raw(f"ws://127.0.0.1:{port}/echo", frame, 2.0)

        result = asyncio.run(run_test())
        assert result.error is None

    def test_raw_handshake_accepts_repeated_upgrade_headers(self):
        async def handler(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            request = await reader.readuntil(b"\r\n\r\n")
            key = None
            for line in request.split(b"\r\n"):
                if line.lower().startswith(b"sec-websocket-key:"):
                    key = line.split(b":", 1)[1].strip().decode()
                    break
            assert key is not None
            digest = hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
            ).digest()
            accept = base64.b64encode(digest)
            writer.write(
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: h2c\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n"
                b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n"
            )
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        async def run_test() -> TransportResult:
            server = await asyncio.start_server(handler, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            async with server:
                frame = build_frame(b"hello", opcode=OP_TEXT, mask=True)
                return await send_raw(f"ws://127.0.0.1:{port}/echo", frame, 2.0)

        result = asyncio.run(run_test())
        assert result.error is None

    def test_raw_wss_with_missing_ca_is_classified(self, tls_echo_server):
        frame = build_frame(b"secure hello", opcode=OP_TEXT, mask=True)
        result = asyncio.run(
            send_raw(
                tls_echo_server.uri,
                frame,
                5.0,
                ConnectOpts(ca_file="/nonexistent/ca.pem"),
            )
        )
        assert isinstance(result, TransportResult)
        assert result.error is not None
        assert result.error_type == "transport_config"


class TestRawFuzzerMode:
    """Test the fuzzer's --raw mode against the echo server."""

    def test_raw_mode_produces_crashes(self, echo_server, tmp_path):
        """Raw mode with mutated frames should trigger protocol errors."""
        from wsfuzz.fuzzer import FuzzConfig, run

        config = FuzzConfig(
            target=echo_server,
            iterations=50,
            max_size=100,
            timeout=2.0,
            log_dir=tmp_path / "crashes",
            raw=True,
        )
        run(config)
        crash_files = list((tmp_path / "crashes").glob("crash_*.bin"))
        # ~91% of frames get reserved opcodes, triggering close code 1002
        assert len(crash_files) > 0, "raw mode should detect protocol errors"

    def test_raw_mode_with_handshake_fuzzing(self, echo_server, tmp_path):
        """--fuzz-handshake should produce crashes from rejected handshakes."""
        from wsfuzz.fuzzer import FuzzConfig, run

        config = FuzzConfig(
            target=echo_server,
            iterations=10,
            max_size=100,
            timeout=2.0,
            log_dir=tmp_path / "crashes",
            raw=True,
            fuzz_handshake=True,
            crash_dedup=False,
        )
        run(config)
        # Handshake fuzzing with random versions/extensions should trigger
        # handshake_failed errors or protocol errors on most iterations
        crash_dir = tmp_path / "crashes"
        assert crash_dir.exists()
        crash_files = list(crash_dir.glob("crash_*.bin"))
        assert len(crash_files) > 0, "handshake fuzzing should produce crashes"


class TestPayloadLengthMismatch:
    """Test frames where declared length != actual payload length.

    Targets buffer pre-allocation bugs (CVE-style): server allocates
    Integer.MAX_VALUE bytes based on the declared length, then crashes.
    """

    def test_fake_large_length_small_payload(self, echo_server):
        """Declare 65535 bytes but send only 5 — server should error or timeout."""
        frame = build_frame(b"hello", opcode=OP_TEXT, mask=True, fake_length=65535)
        result = asyncio.run(send_raw(echo_server, frame, 2.0))
        assert result.error is not None

    def test_fake_zero_length(self, echo_server):
        """Declare 0 bytes but send actual payload — server sees empty message."""
        frame = build_frame(b"surprise", opcode=OP_BINARY, mask=True, fake_length=0)
        result = asyncio.run(send_raw(echo_server, frame, 2.0))
        # Server reads 0 bytes per header, ignores trailing data.
        # Either errors on the trailing bytes or echoes the empty payload.
        if result.error is None:
            assert result.response == b"\x82\x00"  # binary frame, 0-byte payload

    def test_frame_header_encodes_fake_length(self):
        """Verify build_frame uses fake_length in the header."""
        frame = build_frame(b"x", opcode=OP_TEXT, mask=False, fake_length=200)
        # 200 > 125, so 16-bit extended length
        assert frame[1] == 126
        length = struct.unpack("!H", frame[2:4])[0]
        assert length == 200
        # But actual payload is only 1 byte
        assert len(frame) == 4 + 1


class TestCSWSH:
    """Cross-Site WebSocket Hijacking detection.

    Tests whether the server validates the Origin header during handshake.
    A server that accepts arbitrary Origins is vulnerable to CSWSH.
    """

    def test_check_origin_with_valid_origin(self, echo_server):
        """Same-origin connection should succeed."""
        result = asyncio.run(check_origin(echo_server, "http://127.0.0.1", 2.0))
        # Echo server doesn't validate Origin — same-origin accepted
        assert result.error is None

    def test_check_origin_with_evil_origin(self, echo_server):
        """Cross-origin connection — echo server accepts (it's vulnerable)."""
        result = asyncio.run(check_origin(echo_server, "http://evil.example.com", 2.0))
        # Echo server doesn't validate Origin — cross-origin also accepted
        assert result.error is None

    def test_custom_headers_in_raw_mode(self, echo_server):
        """Custom headers should be included in the raw handshake."""
        frame = build_frame(b"test", opcode=OP_TEXT, mask=True)
        opts = ConnectOpts(
            headers={"Cookie": "session=abc123"}, origin="http://test.local"
        )
        result = asyncio.run(send_raw(echo_server, frame, 2.0, opts))
        assert result.error is None
        assert b"test" in result.response

    def test_custom_headers_in_normal_mode(self, echo_server):
        """Custom headers should be passed to websockets.connect."""
        from wsfuzz.transport import send_payload

        opts = ConnectOpts(headers={"Authorization": "Bearer token123"})
        result = asyncio.run(send_payload(echo_server, b"hello", "binary", 2.0, opts))
        assert result.error is None
        assert result.response == b"hello"
