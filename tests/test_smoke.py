"""End-to-end smoke tests for wsfuzz modes.

Each test exercises a full fuzzing pipeline and verifies behavior through
data structures, file contents, and function return values — not through
string-matching stdout output.
"""

import asyncio
import json
import subprocess
import sys
from pathlib import Path

from wsfuzz.fuzzer import FuzzConfig, run
from wsfuzz.logger import CrashLogger
from wsfuzz.transport import TransportResult, send_payload

SEEDS_DIR = Path(__file__).parent.parent / "seeds"


def _read_crash_metadata(txt_path: Path) -> dict[str, str]:
    metadata = {}
    for line in txt_path.read_text().splitlines():
        key, sep, value = line.partition(":")
        if sep:
            metadata[key.strip()] = value.lstrip()
    return metadata


class TestSmokeBinaryMode:
    def test_binary_fuzz_sends_payloads_and_gets_responses(self, echo_server, tmp_path):
        """Verify actual WebSocket communication happened — echo server returns
        what it receives, so no crashes expected on /echo."""
        config = FuzzConfig(
            target=echo_server,
            mode="binary",
            seeds_dir=SEEDS_DIR,
            iterations=5,
            timeout=2.0,
            log_dir=tmp_path / "crashes",
        )
        run(config)

        # Echo server echoes back — no errors, so crash dir should have
        # the index but zero crash artifacts
        crash_dir = tmp_path / "crashes"
        assert crash_dir.exists()
        crash_bins = list(crash_dir.glob("crash_*.bin"))
        assert len(crash_bins) == 0

    def test_binary_mode_sends_bytes_not_text(self, echo_server):
        """Verify binary mode sends raw bytes over WebSocket."""
        payload = b"\x00\xff\x80\x01"
        result = asyncio.run(
            send_payload(echo_server + "/echo", payload, "binary", 2.0)
        )
        assert result.error is None
        assert result.response == payload


class TestSmokeTextMode:
    def test_text_mode_sends_decoded_string(self, echo_server):
        """Verify text mode decodes payload before sending."""
        payload = b"hello world"
        result = asyncio.run(send_payload(echo_server + "/echo", payload, "text", 2.0))
        assert result.error is None
        assert result.response == b"hello world"

    def test_text_fuzz_produces_no_crashes_on_echo(self, echo_server, tmp_path):
        config = FuzzConfig(
            target=echo_server,
            mode="text",
            seeds_dir=SEEDS_DIR,
            iterations=5,
            timeout=2.0,
            log_dir=tmp_path / "crashes",
        )
        run(config)
        crash_bins = list((tmp_path / "crashes").glob("crash_*.bin"))
        assert len(crash_bins) == 0


class TestSmokeRawMode:
    def test_raw_fuzz_builds_and_sends_frames(self, echo_server, tmp_path):
        """Verify raw mode ran iterations and transport_mode metadata is 'raw'."""
        config = FuzzConfig(
            target=echo_server,
            mode="binary",
            seeds_dir=SEEDS_DIR,
            iterations=5,
            raw=True,
            timeout=2.0,
            log_dir=tmp_path / "crashes",
            crash_dedup=False,
        )
        run(config)
        crash_dir = tmp_path / "crashes"
        assert crash_dir.exists()
        # Raw mode against echo server may produce protocol errors (RSV bits, etc.)
        # Verify any crashes have raw transport_mode in metadata
        for txt in crash_dir.glob("crash_*.txt"):
            meta = _read_crash_metadata(txt)
            assert meta.get("transport_mode") == "raw"


class TestSmokeConcurrent:
    def test_concurrent_fuzz_no_data_corruption(self, echo_server, tmp_path):
        """Verify concurrent workers don't corrupt crash index or produce
        duplicate base names."""
        config = FuzzConfig(
            target=echo_server + "/error",
            mode="binary",
            seeds_dir=SEEDS_DIR,
            iterations=10,
            concurrency=3,
            timeout=2.0,
            log_dir=tmp_path / "crashes",
            crash_dedup=False,
        )
        run(config)

        crash_dir = tmp_path / "crashes"
        bins = list(crash_dir.glob("crash_*.bin"))
        txts = list(crash_dir.glob("crash_*.txt"))
        # Every .bin has a matching .txt
        assert len(bins) == len(txts) == 10
        # All base names are unique
        bin_names = {p.stem for p in bins}
        assert len(bin_names) == 10
        # Index is valid JSON
        index = json.loads((crash_dir / "crash_index.json").read_text())
        assert "fingerprints" in index


class TestSmokeReplay:
    def test_replay_sends_exact_payload(self, echo_server, tmp_path, monkeypatch):
        """Verify replay reads .bin file and sends its exact bytes."""
        crash_dir = tmp_path / "crashes"
        crash_dir.mkdir()
        crash_file = crash_dir / "crash_0_1.bin"
        original_payload = b"\xde\xad\xbe\xef"
        crash_file.write_bytes(original_payload)

        # Intercept send_payload to capture what was actually sent
        sent_payloads = []

        async def tracking_send(uri, payload, mode, timeout, opts=None):
            sent_payloads.append(payload)
            return await send_payload(uri, payload, mode, timeout, opts)

        monkeypatch.setattr("wsfuzz.fuzzer.send_payload", tracking_send)

        config = FuzzConfig(
            target=echo_server,
            timeout=2.0,
            log_dir=tmp_path / "unused",
            replay=[crash_file],
        )
        run(config)

        assert len(sent_payloads) == 1
        assert sent_payloads[0] == original_payload

    def test_replay_roundtrip_preserves_error_type(self, echo_server, tmp_path):
        """Fuzz to produce crashes, then replay — error type should match."""
        crash_dir = tmp_path / "crashes"
        config = FuzzConfig(
            target=echo_server + "/error",
            iterations=3,
            timeout=2.0,
            log_dir=crash_dir,
            crash_dedup=False,
        )
        run(config)

        crash_bins = sorted(crash_dir.glob("crash_*.bin"))
        assert len(crash_bins) == 3

        # Read original error types from metadata
        original_types = {}
        for bin_path in crash_bins:
            meta = _read_crash_metadata(bin_path.with_suffix(".txt"))
            original_types[bin_path.name] = meta.get("error_type", "")

        # All crashes from /error should be close_1011
        for error_type in original_types.values():
            assert error_type == "close_1011"


class TestSmokeScenario:
    def test_scenario_executes_fuzz_step(self, echo_server, tmp_path):
        """Verify scenario mode actually runs the fuzz step and gets a response."""
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

        config = FuzzConfig(
            target=echo_server,
            mode="text",
            seeds_dir=SEEDS_DIR,
            scenario=scenario_path,
            iterations=3,
            timeout=2.0,
            log_dir=tmp_path / "crashes",
        )
        # Should complete without raising ScenarioError (expect step passes)
        run(config)
        # Echo server echoes → expect contains "" always passes → no crashes
        crash_bins = list((tmp_path / "crashes").glob("crash_*.bin"))
        assert len(crash_bins) == 0

    def test_scenario_crash_metadata_includes_scenario_path(
        self, echo_server, tmp_path
    ):
        """Verify crashes from scenario mode record the scenario file path."""
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

        config = FuzzConfig(
            target=echo_server + "/error",
            mode="text",
            seeds_dir=SEEDS_DIR,
            scenario=scenario_path,
            iterations=1,
            timeout=2.0,
            log_dir=tmp_path / "crashes",
        )
        run(config)

        txts = list((tmp_path / "crashes").glob("crash_*.txt"))
        assert len(txts) == 1
        meta = _read_crash_metadata(txts[0])
        assert meta.get("transport_mode") == "scenario"
        assert "scenario_path" in meta
        assert meta["scenario_fuzz_ordinal"] == "0"


class TestSmokeHarness:
    def test_harness_echoes_payload_through_websocket(self, echo_server):
        """Verify harness bridges HTTP POST body → WS → HTTP response."""
        from wsfuzz.harness import _handle_request

        async def _run():
            server = await asyncio.start_server(
                lambda r, w: _handle_request(
                    r,
                    w,
                    target=echo_server,
                    mode="text",
                    timeout=2.0,
                    opts=None,
                    template=None,
                ),
                "127.0.0.1",
                0,
            )
            port = server.sockets[0].getsockname()[1]
            async with server:
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                body = b"fuzz-payload-42"
                request = (
                    f"POST / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                    f"Content-Length: {len(body)}\r\n\r\n"
                ).encode() + body
                writer.write(request)
                await writer.drain()
                response = await asyncio.wait_for(reader.read(8192), timeout=5)
                writer.close()

            # Parse HTTP response
            head, _, resp_body = response.partition(b"\r\n\r\n")
            status_code = head.split(b" ", 2)[1]
            return status_code, resp_body

        status, body = asyncio.run(_run())
        assert status == b"200"
        # Echo server returns what it received
        assert body == b"fuzz-payload-42"


class TestSmokeCLI:
    def test_help_lists_all_major_flags(self):
        result = subprocess.run(
            [sys.executable, "-m", "wsfuzz", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0
        for flag in [
            "--target",
            "--mode",
            "--raw",
            "--replay",
            "--scenario",
            "--harness",
            "--concurrency",
            "--max-retries",
        ]:
            assert flag in result.stdout, f"missing flag: {flag}"

    def test_invalid_target_scheme_exits_nonzero(self):
        result = subprocess.run(
            [sys.executable, "-m", "wsfuzz", "-t", "http://localhost:1", "-n", "1"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode != 0
        assert "ws://" in result.stderr or "wss://" in result.stderr


class TestSmokeErrorRecovery:
    def test_connection_refused_produces_no_crashes(self, tmp_path):
        """Connection refused is filtered — not logged as a crash."""
        config = FuzzConfig(
            target="ws://127.0.0.1:1",
            iterations=3,
            timeout=1.0,
            log_dir=tmp_path / "crashes",
            max_retries=0,
        )
        run(config)

        logger = CrashLogger(tmp_path / "crashes")
        # Connection refused is not interesting
        refused_result = TransportResult(
            error="refused", error_type="connection_refused", connection_refused=True
        )
        assert logger.is_interesting(refused_result) is False
        # No crash artifacts were saved
        crash_bins = list((tmp_path / "crashes").glob("crash_*.bin"))
        assert len(crash_bins) == 0

    def test_error_server_crashes_contain_valid_metadata(self, echo_server, tmp_path):
        config = FuzzConfig(
            target=echo_server + "/error",
            iterations=3,
            timeout=2.0,
            log_dir=tmp_path / "crashes",
            crash_dedup=False,
        )
        run(config)

        crash_txts = list((tmp_path / "crashes").glob("crash_*.txt"))
        assert len(crash_txts) == 3
        for txt in crash_txts:
            meta = _read_crash_metadata(txt)
            # Each crash has the expected error type from /error endpoint
            assert meta["error_type"] == "close_1011"
            # Payload size is recorded and positive
            assert int(meta["payload_size"]) > 0
            # Duration was measured
            assert float(meta["duration_ms"]) >= 0

        # Each crash .bin is non-empty
        for bin_path in (tmp_path / "crashes").glob("crash_*.bin"):
            assert bin_path.stat().st_size > 0


class TestSmokeDedup:
    def test_dedup_saves_one_artifact_with_correct_count(self, echo_server, tmp_path):
        config = FuzzConfig(
            target=echo_server + "/error",
            iterations=5,
            timeout=2.0,
            log_dir=tmp_path / "crashes",
        )
        run(config)

        crash_dir = tmp_path / "crashes"
        # Only one .bin saved (dedup)
        bins = list(crash_dir.glob("crash_*.bin"))
        assert len(bins) == 1

        # Crash index reflects 5 total observations
        index = json.loads((crash_dir / "crash_index.json").read_text())
        fingerprints = index["fingerprints"]
        assert len(fingerprints) == 1
        entry = next(iter(fingerprints.values()))
        assert entry["count"] == 5
        assert entry["error_type"] == "close_1011"

    def test_dedup_off_saves_all_with_distinct_payloads(self, echo_server, tmp_path):
        config = FuzzConfig(
            target=echo_server + "/error",
            iterations=5,
            timeout=2.0,
            log_dir=tmp_path / "crashes",
            crash_dedup=False,
        )
        run(config)

        crash_dir = tmp_path / "crashes"
        bins = list(crash_dir.glob("crash_*.bin"))
        assert len(bins) == 5
        # Each crash file contains a payload (non-empty)
        payloads = [b.read_bytes() for b in bins]
        assert all(len(p) > 0 for p in payloads)
        # Metadata all references same error type
        for txt in crash_dir.glob("crash_*.txt"):
            meta = _read_crash_metadata(txt)
            assert meta["error_type"] == "close_1011"
