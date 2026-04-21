"""Unit tests for raw.py internal helper functions.

Tests handshake parsing, validation, host formatting, and close frame parsing
that were previously only tested through integration paths.
"""

import base64
import hashlib
import struct

import pytest

from wsfuzz.raw import (
    HandshakeFuzz,
    _expected_accept,
    _format_host_header,
    _handshake_status_error,
    _parse_close_frame,
    _parse_handshake_headers,
    _request_target,
    _validate_handshake,
    build_frame,
    make_handshake_fuzz,
)

# ---------------------------------------------------------------------------
# _expected_accept
# ---------------------------------------------------------------------------


class TestExpectedAccept:
    def test_known_vector(self):
        """RFC 6455 Section 4.2.2 — known key/accept pair."""
        key = "dGhlIHNhbXBsZSBub25jZQ=="
        expected = base64.b64encode(
            hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
            ).digest()
        ).decode()
        assert _expected_accept(key) == expected

    def test_rfc6455_example(self):
        """The exact example from RFC 6455 Section 4.2.2."""
        # Key from the RFC example
        key = "dGhlIHNhbXBsZSBub25jZQ=="
        # Known correct result from the RFC
        assert _expected_accept(key) == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

    def test_deterministic(self):
        key = "abc123"
        assert _expected_accept(key) == _expected_accept(key)

    def test_different_keys_different_results(self):
        assert _expected_accept("key1") != _expected_accept("key2")


# ---------------------------------------------------------------------------
# _handshake_status_error
# ---------------------------------------------------------------------------


class TestHandshakeStatusError:
    def test_valid_101(self):
        response = b"HTTP/1.1 101 Switching Protocols\r\n\r\n"
        assert _handshake_status_error(response) is None

    def test_not_101(self):
        response = b"HTTP/1.1 200 OK\r\n\r\n"
        assert _handshake_status_error(response) == "status is not 101"

    def test_403_forbidden(self):
        response = b"HTTP/1.1 403 Forbidden\r\n\r\n"
        assert _handshake_status_error(response) == "status is not 101"

    def test_malformed_status_line(self):
        response = b"garbage data\r\n\r\n"
        assert _handshake_status_error(response) == "malformed HTTP status line"

    def test_empty_response(self):
        assert _handshake_status_error(b"") == "malformed HTTP status line"

    def test_only_version_no_status_code(self):
        response = b"HTTP/1.1\r\n\r\n"
        assert _handshake_status_error(response) == "malformed HTTP status line"

    def test_non_ascii_version(self):
        response = b"\xff\xfe/1.1 101 OK\r\n\r\n"
        assert _handshake_status_error(response) == "malformed HTTP status line"


# ---------------------------------------------------------------------------
# _parse_handshake_headers
# ---------------------------------------------------------------------------


class TestParseHandshakeHeaders:
    def test_basic_headers(self):
        response = (
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"\r\n"
        )
        headers = _parse_handshake_headers(response)
        assert headers["upgrade"] == "websocket"
        assert headers["connection"] == "Upgrade"

    def test_case_insensitive_keys(self):
        response = b"HTTP/1.1 101\r\nContent-Type: text/plain\r\n\r\n"
        headers = _parse_handshake_headers(response)
        assert "content-type" in headers
        assert headers["content-type"] == "text/plain"

    def test_duplicate_headers_concatenated(self):
        response = b"HTTP/1.1 101\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n"
        headers = _parse_handshake_headers(response)
        assert headers["set-cookie"] == "a=1,b=2"

    def test_colon_in_value(self):
        response = b"HTTP/1.1 101\r\nLocation: http://example.com:8080\r\n\r\n"
        headers = _parse_handshake_headers(response)
        assert headers["location"] == "http://example.com:8080"

    def test_empty_value(self):
        response = b"HTTP/1.1 101\r\nX-Empty:\r\n\r\n"
        headers = _parse_handshake_headers(response)
        assert headers["x-empty"] == ""

    def test_skips_non_ascii_headers(self):
        response = b"HTTP/1.1 101\r\nX-Good: ok\r\nX-\xff: bad\r\n\r\n"
        headers = _parse_handshake_headers(response)
        assert "x-good" in headers
        assert len(headers) == 1

    def test_skips_lines_without_colon(self):
        response = b"HTTP/1.1 101\r\nno-colon-here\r\nX-Good: ok\r\n\r\n"
        headers = _parse_handshake_headers(response)
        assert headers == {"x-good": "ok"}

    def test_empty_response(self):
        headers = _parse_handshake_headers(b"")
        assert headers == {}

    def test_status_line_excluded(self):
        response = b"HTTP/1.1 101\r\nUpgrade: websocket\r\n\r\n"
        headers = _parse_handshake_headers(response)
        assert "http/1.1 101" not in headers


# ---------------------------------------------------------------------------
# _validate_handshake
# ---------------------------------------------------------------------------


class TestValidateHandshake:
    @staticmethod
    def _valid_response(key: str) -> bytes:
        accept = _expected_accept(key)
        return (
            f"HTTP/1.1 101 Switching Protocols\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            f"\r\n"
        ).encode()

    def test_valid_handshake(self):
        key = "dGhlIHNhbXBsZSBub25jZQ=="
        assert _validate_handshake(self._valid_response(key), key) is None

    def test_bad_status(self):
        response = b"HTTP/1.1 403 Forbidden\r\n\r\n"
        assert _validate_handshake(response, "key") == "status is not 101"

    def test_missing_upgrade(self):
        key = "testkey"
        accept = _expected_accept(key)
        response = (
            f"HTTP/1.1 101 Switching Protocols\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            f"\r\n"
        ).encode()
        assert _validate_handshake(response, key) == "missing Upgrade: websocket"

    def test_missing_connection(self):
        key = "testkey"
        accept = _expected_accept(key)
        response = (
            f"HTTP/1.1 101 Switching Protocols\r\n"
            f"Upgrade: websocket\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            f"\r\n"
        ).encode()
        assert _validate_handshake(response, key) == "missing Connection: Upgrade"

    def test_wrong_accept(self):
        response = (
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: wrong-accept-value\r\n"
            b"\r\n"
        )
        assert _validate_handshake(response, "key") == "invalid Sec-WebSocket-Accept"

    def test_case_insensitive_upgrade(self):
        """Upgrade header value matching should be case-insensitive."""
        key = "testkey"
        accept = _expected_accept(key)
        response = (
            f"HTTP/1.1 101 Switching Protocols\r\n"
            f"Upgrade: WebSocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            f"\r\n"
        ).encode()
        assert _validate_handshake(response, key) is None

    def test_multiple_connection_tokens(self):
        """Connection: keep-alive, Upgrade should still match."""
        key = "testkey"
        accept = _expected_accept(key)
        response = (
            f"HTTP/1.1 101 Switching Protocols\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: keep-alive, Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            f"\r\n"
        ).encode()
        assert _validate_handshake(response, key) is None


# ---------------------------------------------------------------------------
# _format_host_header
# ---------------------------------------------------------------------------


class TestFormatHostHeader:
    def test_ipv4(self):
        assert _format_host_header("127.0.0.1", 8080) == "127.0.0.1:8080"

    def test_hostname(self):
        assert _format_host_header("example.com", 443) == "example.com:443"

    def test_ipv6_bare(self):
        assert _format_host_header("::1", 8080) == "[::1]:8080"

    def test_ipv6_already_bracketed(self):
        assert _format_host_header("[::1]", 8080) == "[::1]:8080"

    def test_ipv6_full(self):
        result = _format_host_header("2001:db8::1", 443)
        assert result == "[2001:db8::1]:443"


# ---------------------------------------------------------------------------
# _request_target
# ---------------------------------------------------------------------------


class TestRequestTarget:
    def test_path_only(self):
        from urllib.parse import urlparse

        parsed = urlparse("ws://example.com/socket")
        assert _request_target(parsed) == "/socket"

    def test_path_with_query(self):
        from urllib.parse import urlparse

        parsed = urlparse("ws://example.com/socket?token=abc")
        assert _request_target(parsed) == "/socket?token=abc"

    def test_no_path_defaults_to_slash(self):
        from urllib.parse import urlparse

        parsed = urlparse("ws://example.com")
        assert _request_target(parsed) == "/"


# ---------------------------------------------------------------------------
# _parse_close_frame edge cases
# ---------------------------------------------------------------------------


class TestParseCloseFrameEdgeCases:
    def test_normal_close_not_error(self):
        """Close code 1000 (normal) should return None — not an error."""
        code = struct.pack("!H", 1000)
        frame = bytes([0x88, len(code)]) + code
        assert _parse_close_frame(frame) is None

    def test_going_away_not_error(self):
        """Close code 1001 (going away) should return None."""
        code = struct.pack("!H", 1001)
        frame = bytes([0x88, len(code)]) + code
        assert _parse_close_frame(frame) is None

    def test_protocol_error_is_error(self):
        code = struct.pack("!H", 1002)
        frame = bytes([0x88, len(code)]) + code
        result = _parse_close_frame(frame)
        assert result is not None
        assert result.close_code == 1002

    def test_close_with_reason(self):
        code = struct.pack("!H", 1008)
        reason = b"policy violation"
        payload = code + reason
        frame = bytes([0x88, len(payload)]) + payload
        result = _parse_close_frame(frame)
        assert result is not None
        assert result.close_code == 1008

    def test_close_1011_internal_error(self):
        code = struct.pack("!H", 1011)
        frame = bytes([0x88, len(code)]) + code
        result = _parse_close_frame(frame)
        assert result is not None
        assert result.close_code == 1011
        assert result.error_type == "close_1011"

    def test_non_close_opcode_returns_none(self):
        """Text frame should not parse as close."""
        frame = bytes([0x81, 0x05]) + b"hello"
        assert _parse_close_frame(frame) is None

    def test_close_with_no_payload(self):
        """Close frame with 0-byte payload (no code) returns None."""
        frame = bytes([0x88, 0x00])
        assert _parse_close_frame(frame) is None

    def test_close_with_one_byte_payload(self):
        """Close frame with 1 byte (incomplete code) should not crash."""
        frame = bytes([0x88, 0x01, 0x03])
        # Should handle gracefully — either None or a result without crash
        result = _parse_close_frame(frame)
        # Implementation detail: 1 byte can't form a 2-byte close code
        assert result is None or result.close_code is None


# ---------------------------------------------------------------------------
# make_handshake_fuzz
# ---------------------------------------------------------------------------


class TestMakeHandshakeFuzz:
    def test_disabled_returns_none(self):
        assert make_handshake_fuzz(enabled=False) is None

    def test_enabled_returns_handshake_fuzz(self):
        result = make_handshake_fuzz(enabled=True)
        assert isinstance(result, HandshakeFuzz)
        assert result.version is not None

    def test_produces_variety(self):
        """Multiple calls should produce different configurations."""
        results = {make_handshake_fuzz(enabled=True).version for _ in range(20)}
        assert len(results) > 1


# ---------------------------------------------------------------------------
# build_frame masking correctness
# ---------------------------------------------------------------------------


class TestBuildFrameMasking:
    def test_masked_frame_can_be_unmasked(self):
        """Verify masking XOR is reversible."""
        payload = b"hello world"
        frame = build_frame(payload, mask=True)
        # Frame: 2 header + 4 mask + payload
        mask_key = frame[2:6]
        masked = frame[6:]
        full_mask = mask_key * (len(masked) // 4 + 1)
        unmasked = bytes(a ^ b for a, b in zip(masked, full_mask, strict=False))
        assert unmasked == payload

    def test_unmasked_frame_payload_is_plaintext(self):
        payload = b"hello"
        frame = build_frame(payload, mask=False)
        # Frame: 2 header + payload (no mask key)
        assert frame[2:] == payload

    def test_empty_payload_masked(self):
        frame = build_frame(b"", mask=True)
        # 2 header + 4 mask + 0 payload = 6 bytes
        assert len(frame) == 6
        # Length field should be 0 (masked bit + 0)
        assert frame[1] == 0x80

    def test_mask_key_is_4_bytes(self):
        frame = build_frame(b"x", mask=True)
        # Mask key starts at offset 2
        mask_key = frame[2:6]
        assert len(mask_key) == 4

    def test_fake_length_with_mask(self):
        """Fake length and mask should work together."""
        frame = build_frame(b"x", mask=True, fake_length=200)
        # 200 > 125 → 16-bit extended: 2 header + 2 extended + 4 mask + 1 payload
        assert len(frame) == 2 + 2 + 4 + 1
        # Length field should encode 200
        length = struct.unpack("!H", frame[2:4])[0]
        assert length == 200

    def test_negative_length_raises(self):
        with pytest.raises(ValueError, match="frame length"):
            build_frame(b"x", fake_length=-1)
