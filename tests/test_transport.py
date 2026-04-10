import asyncio
import os

from wsfuzz.transport import ConnectOpts, TransportResult, send_payload


class TestTransportResult:
    def test_defaults(self):
        r = TransportResult()
        assert r.response is None
        assert r.error is None
        assert r.error_type is None
        assert r.close_code is None
        assert r.duration_ms == 0.0
        assert r.connection_refused is False


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
