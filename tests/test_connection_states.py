"""Tests that both transport modes classify connection states consistently.

Verifies that send_payload (normal) and send_raw (raw) produce the same
error_type, connection_refused, and is_interesting results for every
reachable connection state. Uses classify_error unit tests as the
ground truth, then integration tests against real sockets.
"""

import asyncio
import socket
import threading

from wsfuzz.logger import CrashLogger
from wsfuzz.raw import OP_TEXT, build_frame, send_raw
from wsfuzz.transport import ConnectOpts, TransportResult, classify_error, send_payload

# ---------------------------------------------------------------------------
# Unit tests for classify_error
# ---------------------------------------------------------------------------


class TestClassifyError:
    """classify_error is the single source of truth for error classification."""

    def test_connection_refused(self):
        r = classify_error(ConnectionRefusedError(), 1.0)
        assert r.error_type == "connection_refused"
        assert r.connection_refused is True

    def test_connection_reset(self):
        r = classify_error(ConnectionResetError(), 1.0)
        assert r.error_type == "connection_reset"
        assert r.connection_refused is False

    def test_timeout(self):
        r = classify_error(TimeoutError(), 1.0)
        assert r.error_type == "timeout"
        assert r.connection_refused is False

    def test_oserror_with_connect_call_failed(self):
        """The exact error asyncio raises when both IPv4+IPv6 fail."""
        e = OSError(
            "Multiple exceptions: [Errno 111] Connect call failed "
            "('::1', 64999, 0, 0), [Errno 111] Connect call failed "
            "('127.0.0.1', 64999)"
        )
        r = classify_error(e, 1.0)
        assert r.error_type == "connection_refused"
        assert r.connection_refused is True

    def test_oserror_with_connection_refused_text(self):
        e = OSError("Connection refused")
        r = classify_error(e, 1.0)
        assert r.error_type == "connection_refused"
        assert r.connection_refused is True

    def test_oserror_unrelated(self):
        """A generic OSError that isn't connection-refused."""
        e = OSError("Network is unreachable")
        r = classify_error(e, 1.0)
        assert r.error_type == "OSError"
        assert r.connection_refused is False

    def test_generic_exception(self):
        r = classify_error(ValueError("bad value"), 1.0)
        assert r.error_type == "ValueError"
        assert r.connection_refused is False

    def test_elapsed_ms_preserved(self):
        r = classify_error(ConnectionRefusedError(), 42.5)
        assert r.duration_ms == 42.5

    def test_connection_refused_subclass_priority(self):
        """ConnectionRefusedError is an OSError subclass — must match first."""
        r = classify_error(ConnectionRefusedError("Connection refused"), 1.0)
        assert r.error_type == "connection_refused"
        assert r.connection_refused is True

    def test_connection_reset_subclass_priority(self):
        """ConnectionResetError is an OSError subclass — must match first."""
        r = classify_error(ConnectionResetError("Connection reset by peer"), 1.0)
        assert r.error_type == "connection_reset"
        assert r.connection_refused is False


# ---------------------------------------------------------------------------
# is_interesting must agree with classify_error
# ---------------------------------------------------------------------------


class TestIsInterestingConsistency:
    """Verify that non-crash connection states are filtered by is_interesting."""

    def _logger(self, tmp_path):
        return CrashLogger(tmp_path / "crashes")

    def test_connection_refused_not_interesting(self, tmp_path):
        r = classify_error(ConnectionRefusedError(), 1.0)
        assert not self._logger(tmp_path).is_interesting(r)

    def test_oserror_connect_call_failed_not_interesting(self, tmp_path):
        e = OSError(
            "Multiple exceptions: [Errno 111] Connect call failed "
            "('::1', 1, 0, 0), [Errno 111] Connect call failed ('127.0.0.1', 1)"
        )
        r = classify_error(e, 1.0)
        assert not self._logger(tmp_path).is_interesting(r)

    def test_timeout_not_interesting(self, tmp_path):
        r = classify_error(TimeoutError(), 1.0)
        assert not self._logger(tmp_path).is_interesting(r)

    def test_connection_reset_is_interesting(self, tmp_path):
        r = classify_error(ConnectionResetError(), 1.0)
        assert self._logger(tmp_path).is_interesting(r)

    def test_generic_oserror_is_interesting(self, tmp_path):
        r = classify_error(OSError("Network is unreachable"), 1.0)
        assert self._logger(tmp_path).is_interesting(r)

    def test_no_error_not_interesting(self, tmp_path):
        r = TransportResult()
        assert not self._logger(tmp_path).is_interesting(r)


# ---------------------------------------------------------------------------
# Integration: both modes produce the same classification for real errors
# ---------------------------------------------------------------------------


class TestConnectionRefusedParity:
    """send_payload and send_raw must both classify connection-refused."""

    DEAD_URI = "ws://127.0.0.1:1"  # nothing listening
    # localhost triggers dual-stack (IPv6+IPv4) which raises
    # OSError("Multiple exceptions: ...") instead of ConnectionRefusedError.
    # This is the exact bug path that caused raw mode to log false crashes.
    DEAD_URI_DUALSTACK = "ws://localhost:1"

    def test_send_payload_connection_refused(self):
        r = asyncio.run(send_payload(self.DEAD_URI, b"x", "binary", 1.0))
        assert r.error_type == "connection_refused"
        assert r.connection_refused is True

    def test_send_raw_connection_refused(self):
        frame = build_frame(b"x", opcode=OP_TEXT, mask=True)
        r = asyncio.run(send_raw(self.DEAD_URI, frame, 1.0))
        assert r.error_type == "connection_refused"
        assert r.connection_refused is True

    def test_send_payload_dualstack_refused(self):
        """localhost resolves to both ::1 and 127.0.0.1 — produces OSError."""
        r = asyncio.run(send_payload(self.DEAD_URI_DUALSTACK, b"x", "binary", 1.0))
        assert r.error_type == "connection_refused"
        assert r.connection_refused is True

    def test_send_raw_dualstack_refused(self):
        """The exact scenario that caused the original false-crash bug."""
        frame = build_frame(b"x", opcode=OP_TEXT, mask=True)
        r = asyncio.run(send_raw(self.DEAD_URI_DUALSTACK, frame, 1.0))
        assert r.error_type == "connection_refused"
        assert r.connection_refused is True

    def test_both_filtered_by_is_interesting(self, tmp_path):
        logger = CrashLogger(tmp_path / "crashes")

        r1 = asyncio.run(send_payload(self.DEAD_URI, b"x", "binary", 1.0))
        r2 = asyncio.run(
            send_raw(self.DEAD_URI, build_frame(b"x", opcode=OP_TEXT, mask=True), 1.0)
        )

        assert not logger.is_interesting(r1), (
            f"send_payload refused should not be interesting: {r1.error_type}"
        )
        assert not logger.is_interesting(r2), (
            f"send_raw refused should not be interesting: {r2.error_type}"
        )

    def test_dualstack_filtered_by_is_interesting(self, tmp_path):
        """Dual-stack refused must also be filtered — this was the original bug."""
        logger = CrashLogger(tmp_path / "crashes")

        r1 = asyncio.run(send_payload(self.DEAD_URI_DUALSTACK, b"x", "binary", 1.0))
        r2 = asyncio.run(
            send_raw(
                self.DEAD_URI_DUALSTACK,
                build_frame(b"x", opcode=OP_TEXT, mask=True),
                1.0,
            )
        )

        assert not logger.is_interesting(r1), (
            f"send_payload dualstack refused should not be interesting: {r1.error_type}"
        )
        assert not logger.is_interesting(r2), (
            f"send_raw dualstack refused should not be interesting: {r2.error_type}"
        )


class TestTimeoutParity:
    """Both modes must classify timeouts identically."""

    def test_send_payload_timeout(self, echo_server):
        r = asyncio.run(send_payload(echo_server + "/slow", b"x", "binary", 0.3))
        assert r.error_type == "timeout"
        assert r.connection_refused is False

    def test_send_raw_timeout(self, echo_server):
        frame = build_frame(b"x", opcode=OP_TEXT, mask=True)
        r = asyncio.run(send_raw(echo_server + "/slow", frame, 0.3))
        assert r.error_type == "timeout"
        assert r.connection_refused is False


class TestConnectionResetParity:
    """Both modes must classify connection resets identically."""

    @staticmethod
    def _reset_server() -> tuple[str, threading.Event]:
        """Start a TCP server that accepts and immediately RSTs the connection."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        sock.listen(8)
        port = sock.getsockname()[1]
        stop = threading.Event()

        def _serve():
            while not stop.is_set():
                sock.settimeout(0.5)
                try:
                    conn, _ = sock.accept()
                    # Set SO_LINGER with timeout 0 to send RST on close
                    conn.setsockopt(
                        socket.SOL_SOCKET,
                        socket.SO_LINGER,
                        b"\x01\x00\x00\x00\x00\x00\x00\x00",
                    )
                    conn.close()
                except TimeoutError:
                    pass
            sock.close()

        thread = threading.Thread(target=_serve, daemon=True)
        thread.start()
        return f"ws://127.0.0.1:{port}", stop

    def test_send_payload_connection_reset(self):
        uri, stop = self._reset_server()
        try:
            r = asyncio.run(send_payload(uri, b"x", "binary", 1.0))
            # websockets may wrap the RST as InvalidMessage during handshake,
            # but it must never be classified as connection_refused or timeout
            assert r.connection_refused is False
            assert r.error_type not in ("connection_refused", "timeout", None)
        finally:
            stop.set()

    def test_send_raw_connection_reset(self):
        uri, stop = self._reset_server()
        try:
            frame = build_frame(b"x", opcode=OP_TEXT, mask=True)
            r = asyncio.run(send_raw(uri, frame, 1.0))
            assert r.error_type == "connection_reset"
            assert r.connection_refused is False
        finally:
            stop.set()

    def test_both_reset_are_interesting(self, tmp_path):
        """Connection resets must be flagged as interesting in both modes."""
        logger = CrashLogger(tmp_path / "crashes")

        uri, stop = self._reset_server()
        try:
            r1 = asyncio.run(send_payload(uri, b"x", "binary", 1.0))
            r2 = asyncio.run(
                send_raw(uri, build_frame(b"x", opcode=OP_TEXT, mask=True), 1.0)
            )
            assert logger.is_interesting(r1), (
                f"send_payload reset should be interesting: {r1.error_type}"
            )
            assert logger.is_interesting(r2), (
                f"send_raw reset should be interesting: {r2.error_type}"
            )
        finally:
            stop.set()


class TestNormalOperationParity:
    """Both modes return clean results for a healthy server."""

    def test_send_payload_success(self, echo_server):
        r = asyncio.run(send_payload(echo_server + "/echo", b"ping", "binary", 5.0))
        assert r.error is None
        assert r.error_type is None
        assert r.connection_refused is False
        assert r.response == b"ping"

    def test_send_raw_success(self, echo_server):
        frame = build_frame(b"hello", opcode=OP_TEXT, mask=True)
        r = asyncio.run(send_raw(echo_server + "/echo", frame, 5.0))
        assert r.error is None
        assert r.connection_refused is False
        assert r.response is not None


class TestCustomHeadersParity:
    """Custom headers/origin work in both modes without affecting classification."""

    def test_send_payload_with_opts(self, echo_server):
        opts = ConnectOpts(headers={"X-Test": "1"}, origin="http://test.local")
        r = asyncio.run(send_payload(echo_server + "/echo", b"x", "binary", 5.0, opts))
        assert r.error is None

    def test_send_raw_with_opts(self, echo_server):
        opts = ConnectOpts(headers={"X-Test": "1"}, origin="http://test.local")
        frame = build_frame(b"x", opcode=OP_TEXT, mask=True)
        r = asyncio.run(send_raw(echo_server + "/echo", frame, 5.0, opts))
        assert r.error is None

    def test_refused_with_opts_consistent(self):
        opts = ConnectOpts(headers={"Cookie": "s=1"})
        r1 = asyncio.run(send_payload("ws://127.0.0.1:1", b"x", "binary", 1.0, opts))
        r2 = asyncio.run(
            send_raw(
                "ws://127.0.0.1:1",
                build_frame(b"x", opcode=OP_TEXT, mask=True),
                1.0,
                opts,
            )
        )
        assert r1.error_type == r2.error_type == "connection_refused"
