import asyncio
import os
from typing import Any, cast

import pytest

from wsfuzz.raw import build_frame, send_raw
from wsfuzz.transport import (
    ConnectOpts,
    TransportResult,
    make_connect_opts,
    send_payload,
    validate_ws_uri,
)


class TestTransportResult:
    def test_defaults(self):
        r = TransportResult()
        assert r.response is None
        assert r.error is None
        assert r.error_type is None
        assert r.close_code is None
        assert r.duration_ms == 0.0
        assert r.connection_refused is False


class TestConnectOpts:
    def test_rejects_header_newlines(self):
        with pytest.raises(ValueError, match="headers must not contain newlines"):
            make_connect_opts({"X-Test": "ok\r\nX-Evil: 1"})

    def test_rejects_header_control_characters(self):
        with pytest.raises(
            ValueError,
            match="headers must not contain control characters",
        ):
            make_connect_opts({"X-Test": "ok\x0bbad"})

    def test_rejects_empty_header_name(self):
        with pytest.raises(ValueError, match="header names must not be empty"):
            make_connect_opts({" ": "value"})

    def test_rejects_invalid_header_name(self):
        with pytest.raises(ValueError, match="header names must be valid HTTP tokens"):
            make_connect_opts({"Bad Header": "value"})

    def test_rejects_header_name_surrounding_spaces(self):
        with pytest.raises(ValueError, match="header names must be valid HTTP tokens"):
            make_connect_opts({" X-Test": "value"})

    def test_rejects_origin_newlines(self):
        with pytest.raises(ValueError, match="origin must not contain newlines"):
            make_connect_opts(origin="https://example.test\r\nX-Evil: 1")

    def test_rejects_origin_control_characters(self):
        with pytest.raises(
            ValueError,
            match="origin must not contain control characters",
        ):
            make_connect_opts(origin="https://example.test\x0bbad")

    def test_rejects_non_string_headers(self):
        headers = cast(dict[str, str], {"X-Test": cast(Any, 123)})
        with pytest.raises(ValueError, match="headers must be strings"):
            make_connect_opts(headers)


class TestValidateWsUri:
    @pytest.mark.parametrize(
        ("uri", "message"),
        [
            ("ws://:123/socket", "target must include a host"),
            (
                "ws://example.test:bad/socket",
                "target port must be between 1 and 65535",
            ),
            (
                "ws://example.test:0/socket",
                "target port must be between 1 and 65535",
            ),
            (
                "ws://user:pass@example.test/socket",
                "target must not contain userinfo",
            ),
        ],
    )
    def test_rejects_invalid_authority(self, uri, message):
        with pytest.raises(ValueError, match=message):
            validate_ws_uri(uri)

    def test_rejects_fragments(self):
        with pytest.raises(ValueError, match="target must not contain fragments"):
            validate_ws_uri("ws://example.test/socket#client-state")

    def test_rejects_control_characters(self):
        with pytest.raises(
            ValueError,
            match="target must not contain control characters",
        ):
            validate_ws_uri("ws://example.test/socket\x0bcontrol")


class TestSendPayload:
    def test_echo_binary(self, echo_server):
        payload = b"\x00\x01\x02\x03"
        result = asyncio.run(
            send_payload(echo_server + "/echo", payload, "binary", 5.0)
        )
        assert result.error is None
        assert result.response == payload
        assert result.duration_ms > 0

    def test_echo_text(self, echo_server):
        payload = b"hello world"
        result = asyncio.run(send_payload(echo_server + "/echo", payload, "text", 5.0))
        assert result.error is None
        assert result.response == payload

    def test_echo_large_payload(self, echo_server):
        payload = os.urandom(4096)
        result = asyncio.run(
            send_payload(echo_server + "/echo", payload, "binary", 5.0)
        )
        assert result.error is None
        assert result.response == payload

    def test_echo_default_path(self, echo_server):
        payload = b"default path test"
        result = asyncio.run(send_payload(echo_server, payload, "binary", 5.0))
        assert result.error is None
        assert result.response == payload

    def test_server_close(self, echo_server):
        payload = b"test"
        result = asyncio.run(
            send_payload(echo_server + "/close", payload, "binary", 5.0)
        )
        assert result.connection_refused is False

    def test_server_error_close_code(self, echo_server):
        payload = b"test"
        result = asyncio.run(
            send_payload(echo_server + "/error", payload, "binary", 5.0)
        )
        assert result.close_code == 1011
        assert result.error_type == "close_1011"

    def test_connection_refused(self):
        result = asyncio.run(send_payload("ws://127.0.0.1:1", b"test", "binary", 1.0))
        assert result.connection_refused is True

    def test_timeout(self, echo_server):
        result = asyncio.run(send_payload(echo_server + "/slow", b"x", "binary", 0.5))
        assert result.error_type == "timeout"

    def test_binary_payload_with_text_mode(self, echo_server):
        payload = b"\xff\xfe\xfd"  # invalid UTF-8
        result = asyncio.run(send_payload(echo_server + "/echo", payload, "text", 5.0))
        # Should not crash — decode with errors="replace"
        assert isinstance(result, TransportResult)

    def test_null_bytes_binary(self, echo_server):
        payload = b"\x00" * 100
        result = asyncio.run(
            send_payload(echo_server + "/echo", payload, "binary", 5.0)
        )
        assert result.error is None
        assert result.response == payload

    def test_wss_with_custom_ca(self, tls_echo_server):
        payload = b"hello over tls"
        result = asyncio.run(
            send_payload(
                tls_echo_server.uri + "/echo",
                payload,
                "binary",
                5.0,
                ConnectOpts(ca_file=str(tls_echo_server.cert_path)),
            )
        )
        assert result.error is None
        assert result.response == payload

    def test_wss_with_insecure(self, tls_echo_server):
        payload = b"insecure tls"
        result = asyncio.run(
            send_payload(
                tls_echo_server.uri + "/echo",
                payload,
                "binary",
                5.0,
                ConnectOpts(insecure=True),
            )
        )
        assert result.error is None
        assert result.response == payload

    def test_wss_with_missing_ca_is_classified(self, tls_echo_server):
        result = asyncio.run(
            send_payload(
                tls_echo_server.uri + "/echo",
                b"test",
                "binary",
                5.0,
                ConnectOpts(ca_file="/nonexistent/ca.pem"),
            )
        )
        assert isinstance(result, TransportResult)
        assert result.error is not None
        assert result.error_type == "transport_config"

    def test_invalid_direct_connect_opts_are_config_error(self):
        result = asyncio.run(
            send_payload(
                "ws://127.0.0.1:1",
                b"test",
                "binary",
                1.0,
                ConnectOpts(origin="https://example.test\r\nX-Evil: 1"),
            )
        )

        assert result.error_type == "transport_config"

    def test_invalid_direct_raw_connect_opts_are_config_error(self):
        result = asyncio.run(
            send_raw(
                "ws://127.0.0.1:1",
                build_frame(b"test"),
                1.0,
                ConnectOpts(headers={"X-Test": "ok\r\nX-Evil: 1"}),
            )
        )

        assert result.error_type == "transport_config"
