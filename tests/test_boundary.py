"""Boundary value and edge case tests.

Tests frame length transitions, template edge cases, crash index resilience,
harness concurrency, negative security, and scenario error recovery.
"""

import asyncio
import json
import struct
from pathlib import Path

import pytest

from wsfuzz.fuzzer import FuzzConfig, run
from wsfuzz.harness import _handle_request
from wsfuzz.logger import CrashLogger
from wsfuzz.raw import OP_BINARY, OP_TEXT, build_frame, send_raw
from wsfuzz.scenario import (
    ScenarioError,
    ScenarioSession,
    _render_value,
    _serialize_message,
    load_scenario,
    run_scenario_iteration,
    select_fuzz_step,
)
from wsfuzz.transport import ConnectOpts, TransportResult, send_payload

SEEDS_DIR = Path(__file__).parent.parent / "seeds"


# ---------------------------------------------------------------------------
# 1. Frame length boundary transitions
# ---------------------------------------------------------------------------


class TestFrameLengthBoundaries:
    """Test frame encoding at exact boundary values: 125, 126, 65535, 65536."""

    def test_125_bytes_uses_7bit_length(self):
        payload = b"A" * 125
        frame = build_frame(payload, mask=False)
        assert frame[1] == 125  # 7-bit length field

    def test_126_bytes_uses_16bit_length(self):
        payload = b"A" * 126
        frame = build_frame(payload, mask=False)
        assert frame[1] == 126  # extended 16-bit marker
        length = struct.unpack("!H", frame[2:4])[0]
        assert length == 126

    def test_65535_bytes_uses_16bit_length(self):
        payload = b"A" * 65535
        frame = build_frame(payload, mask=False)
        assert frame[1] == 126  # still 16-bit
        length = struct.unpack("!H", frame[2:4])[0]
        assert length == 65535

    def test_65536_bytes_uses_64bit_length(self):
        payload = b"A" * 65536
        frame = build_frame(payload, mask=False)
        assert frame[1] == 127  # 64-bit marker
        length = struct.unpack("!Q", frame[2:10])[0]
        assert length == 65536

    def test_fake_length_125_in_7bit(self):
        frame = build_frame(b"x", mask=False, fake_length=125)
        assert frame[1] == 125

    def test_fake_length_126_in_16bit(self):
        frame = build_frame(b"x", mask=False, fake_length=126)
        assert frame[1] == 126
        length = struct.unpack("!H", frame[2:4])[0]
        assert length == 126

    def test_fake_length_65536_in_64bit(self):
        frame = build_frame(b"x", mask=False, fake_length=65536)
        assert frame[1] == 127
        length = struct.unpack("!Q", frame[2:10])[0]
        assert length == 65536

    def test_zero_length_payload(self):
        frame = build_frame(b"", opcode=OP_BINARY, mask=False)
        assert frame[1] == 0

    def test_masked_125_byte_frame_has_correct_total_size(self):
        payload = b"A" * 125
        frame = build_frame(payload, mask=True)
        # 2 header + 4 mask + 125 payload = 131
        assert len(frame) == 131

    def test_masked_126_byte_frame_has_correct_total_size(self):
        payload = b"A" * 126
        frame = build_frame(payload, mask=True)
        # 2 header + 2 extended length + 4 mask + 126 payload = 134
        assert len(frame) == 134


# ---------------------------------------------------------------------------
# 2. Template edge cases
# ---------------------------------------------------------------------------


class TestTemplateEdgeCases:
    """Test _render_value and _serialize_message directly — no full pipeline."""

    def test_multiple_fuzz_markers_both_replaced(self):
        """Both [FUZZ] markers in a string template get the same payload."""
        result = _render_value("[FUZZ]-[FUZZ]", {}, b"abc", "text")
        assert result == "abc-abc"

    def test_multiple_fuzz_markers_serialize_text(self):
        msg = _serialize_message("[FUZZ]-[FUZZ]", "text", {}, b"hello")
        assert isinstance(msg, str)
        assert msg == "hello-hello"

    def test_multiple_fuzz_markers_serialize_binary(self):
        msg = _serialize_message("[FUZZ]-[FUZZ]", "binary", {}, b"xy")
        assert isinstance(msg, bytes)
        assert msg == b"xy-xy"

    def test_deeply_nested_json_template(self):
        template = {"a": {"b": {"c": {"d": "[FUZZ]"}}}}
        result = _render_value(template, {}, b"deep", "text")
        assert result == {"a": {"b": {"c": {"d": "deep"}}}}

    def test_deeply_nested_serializes_to_json(self):
        template = {"a": {"b": "[FUZZ]"}}
        msg = _serialize_message(template, "text", {}, b"val")
        parsed = json.loads(msg)
        assert parsed == {"a": {"b": "val"}}

    def test_fuzz_in_array_template(self):
        template = ["a", "[FUZZ]", "c"]
        result = _render_value(template, {}, b"middle", "text")
        assert result == ["a", "middle", "c"]

    def test_fuzz_in_array_serializes_to_json(self):
        template = ["a", "[FUZZ]", "c"]
        msg = _serialize_message(template, "text", {}, b"B")
        parsed = json.loads(msg)
        assert parsed == ["a", "B", "c"]

    def test_variable_interpolation_in_render(self):
        variables = {"msg": "captured-value"}
        result = _render_value(
            {"echo": "${msg}", "data": "[FUZZ]"}, variables, b"fuzzed", "text"
        )
        assert result == {"echo": "captured-value", "data": "fuzzed"}

    def test_variable_interpolation_serializes_to_json(self):
        variables = {"msg": "captured-value"}
        template = {"echo": "${msg}", "data": "[FUZZ]"}
        msg = _serialize_message(template, "text", variables, b"fuzzed")
        parsed = json.loads(msg)
        assert parsed == {"echo": "captured-value", "data": "fuzzed"}

    def test_bare_fuzz_in_binary_mode_returns_bytes(self):
        result = _render_value("[FUZZ]", {}, b"\xff\x00", "binary")
        assert result == b"\xff\x00"

    def test_bare_fuzz_in_text_mode_returns_string(self):
        result = _render_value("[FUZZ]", {}, b"text-payload", "text")
        assert result == "text-payload"

    def test_non_string_values_pass_through(self):
        template = {"count": 42, "active": True, "data": "[FUZZ]"}
        result = _render_value(template, {}, b"x", "text")
        assert result["count"] == 42
        assert result["active"] is True
        assert result["data"] == "x"

    def test_fuzz_outside_active_step_raises(self):
        with pytest.raises(ScenarioError, match=r"\[FUZZ\] used outside"):
            _render_value("[FUZZ]", {}, None, "text")

    def test_undefined_variable_raises(self):
        with pytest.raises(ScenarioError, match="not defined"):
            _render_value("${missing}", {}, None, "text")


# ---------------------------------------------------------------------------
# 3. Crash index resilience
# ---------------------------------------------------------------------------


class TestCrashIndexResilience:
    def test_index_with_wrong_root_type(self, tmp_path):
        (tmp_path / "crash_index.json").write_text('"a string"')
        logger = CrashLogger(tmp_path)
        assert logger._fingerprints == {}
        result = TransportResult(error="err", error_type="SomeError")
        logged = logger.log_crash(0, b"x", result, 0, 1)
        assert logged.saved is True

    def test_index_with_missing_fingerprints_key(self, tmp_path):
        (tmp_path / "crash_index.json").write_text('{"other": "data"}')
        logger = CrashLogger(tmp_path)
        assert logger._fingerprints == {}

    def test_index_with_array_fingerprints(self, tmp_path):
        (tmp_path / "crash_index.json").write_text('{"fingerprints": []}')
        logger = CrashLogger(tmp_path)
        assert logger._fingerprints == {}

    def test_index_entry_with_non_dict_value(self, tmp_path):
        (tmp_path / "crash_index.json").write_text(
            '{"fingerprints": {"abc": "not a dict"}}'
        )
        logger = CrashLogger(tmp_path)
        assert logger._fingerprints == {}

    def test_index_entry_with_missing_count(self, tmp_path):
        (tmp_path / "crash_0.bin").write_bytes(b"x")
        (tmp_path / "crash_0.txt").write_text("err\n")
        (tmp_path / "crash_index.json").write_text(
            json.dumps(
                {"fingerprints": {"abc": {"first": "crash_0", "error_type": "e"}}}
            )
        )
        logger = CrashLogger(tmp_path)
        assert logger._fingerprints == {}

    def test_index_entry_with_missing_first(self, tmp_path):
        (tmp_path / "crash_index.json").write_text(
            json.dumps({"fingerprints": {"abc": {"count": 1, "error_type": "e"}}})
        )
        logger = CrashLogger(tmp_path)
        assert logger._fingerprints == {}

    def test_index_survives_deleted_bin_only(self, tmp_path):
        """If .bin is deleted but .txt remains, entry is invalidated."""
        logger = CrashLogger(tmp_path)
        result = TransportResult(error="err", error_type="SomeError")
        first = logger.log_crash(0, b"x", result, 0, 1)
        assert first.saved is True

        # Delete only .bin, keep .txt
        for f in tmp_path.glob("crash_*.bin"):
            f.unlink()

        logger2 = CrashLogger(tmp_path)
        second = logger2.log_crash(1, b"y", result, 0, 2)
        assert second.saved is True

    def test_index_survives_deleted_txt_only(self, tmp_path):
        """If .txt is deleted but .bin remains, entry is invalidated."""
        logger = CrashLogger(tmp_path)
        result = TransportResult(error="err", error_type="SomeError")
        first = logger.log_crash(0, b"x", result, 0, 1)
        assert first.saved is True

        for f in tmp_path.glob("crash_*.txt"):
            f.unlink()

        logger2 = CrashLogger(tmp_path)
        second = logger2.log_crash(1, b"y", result, 0, 2)
        assert second.saved is True

    def test_index_truncated_json(self, tmp_path):
        (tmp_path / "crash_index.json").write_text('{"fingerprints": {')
        logger = CrashLogger(tmp_path)
        assert logger._fingerprints == {}


# ---------------------------------------------------------------------------
# 4. Harness concurrency
# ---------------------------------------------------------------------------


def _harness_handler(reader, writer, target, mode="text", timeout=5.0):
    return _handle_request(
        reader,
        writer,
        target=target,
        mode=mode,
        timeout=timeout,
        opts=None,
        template=None,
    )


class TestHarnessConcurrency:
    def test_multiple_simultaneous_requests(self, echo_server):
        loop = asyncio.new_event_loop()

        async def _run():
            server = await asyncio.start_server(
                lambda r, w: _harness_handler(r, w, echo_server),
                "127.0.0.1",
                0,
            )
            port = server.sockets[0].getsockname()[1]
            async with server:
                tasks = []
                for i in range(5):
                    tasks.append(_send_http_request(port, f"msg-{i}".encode()))
                results = await asyncio.gather(*tasks)
                for i, (status, body) in enumerate(results):
                    assert status == b"200", f"request {i} failed: {status}"
                    assert f"msg-{i}".encode() in body

        loop.run_until_complete(_run())
        loop.close()


async def _send_http_request(port: int, body: bytes) -> tuple[bytes, bytes]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    request = (
        f"POST / HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
    ).encode() + body
    writer.write(request)
    await writer.drain()
    response = await asyncio.wait_for(reader.read(8192), timeout=10)
    writer.close()
    status_line = response.split(b"\r\n", 1)[0]
    status_code = status_line.split(b" ", 2)[1]
    _, _, resp_body = response.partition(b"\r\n\r\n")
    return status_code, resp_body


# ---------------------------------------------------------------------------
# 5. Negative security — path traversal in crash metadata
# ---------------------------------------------------------------------------


class TestCrashMetadataPathTraversal:
    def test_replay_with_traversal_scenario_path_raises_error(
        self, echo_server, tmp_path
    ):
        """Crafted metadata with path traversal in scenario_path should
        raise ScenarioError rather than reading arbitrary files."""
        from wsfuzz.scenario import ScenarioError

        crash_dir = tmp_path / "crashes"
        crash_dir.mkdir()
        crash_file = crash_dir / "crash_0_1.bin"
        crash_file.write_bytes(b"payload")
        crash_file.with_suffix(".txt").write_text(
            "transport_mode: scenario\n"
            "scenario_path: ../../../nonexistent.json\n"
            "message_mode: text\n"
        )

        config = FuzzConfig(
            target=echo_server,
            timeout=2.0,
            log_dir=tmp_path / "unused",
            replay=[crash_file],
        )
        with pytest.raises(ScenarioError, match="scenario file cannot be read"):
            run(config)

    def test_crash_base_name_rejects_path_separators(self, tmp_path):
        """Ensure the logger never creates artifacts with / or \\ in base name."""
        logger = CrashLogger(tmp_path)
        result = TransportResult(error="err", error_type="SomeError")
        logged = logger.log_crash(0, b"x", result, 0, 1)
        assert logged.base_name is not None
        assert "/" not in logged.base_name
        assert "\\" not in logged.base_name


# ---------------------------------------------------------------------------
# 6. Scenario error recovery — mid-session disconnect
# ---------------------------------------------------------------------------


class TestScenarioErrorRecovery:
    def test_scenario_session_reconnects_after_error(self, echo_server, tmp_path):
        scenario_path = tmp_path / "scenario.json"
        scenario_path.write_text(
            json.dumps(
                {
                    "steps": [
                        {"fuzz": "[FUZZ]"},
                        {"expect": {"contains": ""}},
                    ]
                }
            )
        )
        scenario = load_scenario(scenario_path)

        async def _run():
            session = ScenarioSession(scenario, echo_server, "text", 2.0, None)
            fuzz_step = select_fuzz_step(scenario, 0, "round-robin")

            # First run — should succeed
            result1 = await session.run(b"hello", fuzz_step)
            assert result1.error is None

            # Close session explicitly to simulate disconnect
            await session.close()
            assert session._ws is None

            # Next run — should reconnect automatically
            result2 = await session.run(b"world", fuzz_step)
            assert result2.error is None
            await session.close()

        asyncio.run(_run())

    def test_scenario_connection_refused_returns_error(self, tmp_path):
        scenario_path = tmp_path / "scenario.json"
        scenario_path.write_text(json.dumps({"steps": [{"fuzz": "[FUZZ]"}]}))
        scenario = load_scenario(scenario_path)
        fuzz_step = select_fuzz_step(scenario, 0, "round-robin")

        result = asyncio.run(
            run_scenario_iteration(
                scenario, "ws://127.0.0.1:1", b"x", "text", 1.0, None, fuzz_step
            )
        )
        assert result.error is not None
        assert result.connection_refused is True

    def test_scenario_session_reuse_after_server_error(self, echo_server, tmp_path):
        scenario_path = tmp_path / "scenario.json"
        scenario_path.write_text(
            json.dumps(
                {
                    "steps": [
                        {"fuzz": "[FUZZ]"},
                    ]
                }
            )
        )
        config = FuzzConfig(
            target=echo_server + "/error",
            mode="text",
            seeds_dir=SEEDS_DIR,
            scenario=scenario_path,
            scenario_reuse_connection=True,
            iterations=3,
            timeout=2.0,
            log_dir=tmp_path / "crashes",
        )
        run(config)

        crash_bins = list((tmp_path / "crashes").glob("crash_*.bin"))
        assert len(crash_bins) >= 1


# ---------------------------------------------------------------------------
# 7. TLS error paths
# ---------------------------------------------------------------------------


class TestTlsErrorPaths:
    def test_wss_without_insecure_fails_self_signed(self, tls_echo_server):
        """Connecting to a self-signed cert without --insecure or CA should fail."""
        result = asyncio.run(
            send_payload(tls_echo_server.uri + "/echo", b"test", "binary", 2.0)
        )
        assert result.error is not None

    def test_wss_with_wrong_ca_fails(self, tls_echo_server, tmp_path):
        wrong_ca = tmp_path / "wrong_ca.pem"
        wrong_ca.write_text(
            "-----BEGIN CERTIFICATE-----\nnotreal\n-----END CERTIFICATE-----\n"
        )
        result = asyncio.run(
            send_payload(
                tls_echo_server.uri + "/echo",
                b"test",
                "binary",
                2.0,
                ConnectOpts(ca_file=str(wrong_ca)),
            )
        )
        assert result.error is not None

    def test_wss_with_correct_ca_succeeds(self, tls_echo_server):
        result = asyncio.run(
            send_payload(
                tls_echo_server.uri + "/echo",
                b"test",
                "binary",
                2.0,
                ConnectOpts(ca_file=str(tls_echo_server.cert_path)),
            )
        )
        assert result.error is None
        assert result.response == b"test"

    def test_wss_insecure_bypasses_verification(self, tls_echo_server):
        result = asyncio.run(
            send_payload(
                tls_echo_server.uri + "/echo",
                b"test",
                "binary",
                2.0,
                ConnectOpts(insecure=True),
            )
        )
        assert result.error is None
        assert result.response == b"test"

    def test_raw_wss_insecure(self, tls_echo_server):
        frame = build_frame(b"test", opcode=OP_TEXT, mask=True)
        result = asyncio.run(
            send_raw(
                tls_echo_server.uri + "/echo",
                frame,
                2.0,
                ConnectOpts(insecure=True),
            )
        )
        # Should complete without connection error
        assert result.error_type != "connection_refused"


# ---------------------------------------------------------------------------
# 8. Close frame boundary parsing
# ---------------------------------------------------------------------------


class TestCloseFrameParsing:
    def test_masked_close_frame(self):
        """Close frame with server-side masking should still parse."""
        from wsfuzz.raw import _parse_close_frame

        code_bytes = struct.pack("!H", 1008)
        reason = b"policy"
        payload = code_bytes + reason

        # Build a masked close frame manually
        mask_key = b"\x01\x02\x03\x04"
        masked_payload = bytes(
            a ^ b for a, b in zip(payload, (mask_key * 3)[: len(payload)], strict=False)
        )

        frame = bytes([0x88, 0x80 | len(payload)]) + mask_key + masked_payload
        result = _parse_close_frame(frame)
        assert result is not None
        assert result.close_code == 1008

    def test_extended_16bit_close_frame(self):
        """Close frame with 16-bit extended length (unusual but valid encoding)."""
        from wsfuzz.raw import _parse_close_frame

        code_bytes = struct.pack("!H", 1011)
        reason = b"x" * 200  # > 125 bytes to force 16-bit length
        payload = code_bytes + reason

        first_byte = 0x88  # FIN + CLOSE
        header = struct.pack("!BBH", first_byte, 126, len(payload))
        frame = header + payload
        result = _parse_close_frame(frame)
        assert result is not None
        assert result.close_code == 1011
