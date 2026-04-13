import asyncio
import hashlib
import json
import time
from pathlib import Path

import pytest

from wsfuzz.fuzzer import FuzzConfig, run
from wsfuzz.raw import HandshakeFuzz
from wsfuzz.scenario import ScenarioError
from wsfuzz.transport import TransportResult


class TestFuzzerIntegration:
    def test_programmatic_config_rejects_invalid_target(self, tmp_path):
        with pytest.raises(ValueError, match="target must be a ws:// or wss:// URL"):
            run(
                FuzzConfig(
                    target="http://127.0.0.1:1",
                    iterations=1,
                    log_dir=tmp_path / "crashes",
                )
            )

    def test_programmatic_config_rejects_invalid_mode(self, tmp_path):
        with pytest.raises(ValueError, match="mode must be 'text' or 'binary'"):
            run(
                FuzzConfig(
                    target="ws://127.0.0.1:1",
                    mode="invalid",
                    iterations=1,
                    log_dir=tmp_path / "crashes",
                )
            )

    @pytest.mark.parametrize(
        ("field", "value", "message"),
        [
            ("iterations", -1, "iterations must be non-negative"),
            ("max_size", 0, "max_size must be positive"),
            ("timeout", 0, "timeout must be positive"),
            ("timeout", float("nan"), "timeout must be positive"),
            ("timeout", float("inf"), "timeout must be positive"),
            ("concurrency", 0, "concurrency must be positive"),
            ("max_retries", -1, "max_retries must be non-negative"),
            (
                "scenario_session_history_limit",
                -1,
                "scenario_session_history_limit must be non-negative",
            ),
        ],
    )
    def test_programmatic_config_rejects_invalid_numeric_values(
        self, tmp_path, field, value, message
    ):
        config = FuzzConfig(
            target="ws://127.0.0.1:1",
            iterations=1,
            log_dir=tmp_path / "crashes",
        )
        setattr(config, field, value)

        with pytest.raises(ValueError, match=message):
            run(config)

    @pytest.mark.parametrize(
        ("field", "value", "message"),
        [
            (
                "headers",
                {"Bad Header": "value"},
                "header names must be valid HTTP tokens",
            ),
            (
                "origin",
                "https://example.test\x0bbad",
                "origin must not contain control characters",
            ),
        ],
    )
    def test_programmatic_config_rejects_invalid_connect_options_early(
        self, tmp_path, field, value, message
    ):
        log_dir = tmp_path / "crashes"
        config = FuzzConfig(
            target="ws://127.0.0.1:1",
            iterations=1,
            log_dir=log_dir,
        )
        setattr(config, field, value)

        with pytest.raises(ValueError, match=message):
            run(config)

        assert not log_dir.exists()

    def test_programmatic_config_rejects_missing_replay_file_early(self, tmp_path):
        log_dir = tmp_path / "crashes"
        replay_file = tmp_path / "missing.bin"

        with pytest.raises(ValueError, match="replay file does not exist"):
            run(
                FuzzConfig(
                    target="ws://127.0.0.1:1",
                    replay=[replay_file],
                    log_dir=log_dir,
                )
            )

        assert not log_dir.exists()

    def test_programmatic_config_rejects_non_bin_replay_file_early(self, tmp_path):
        log_dir = tmp_path / "crashes"
        replay_file = tmp_path / "crash_0.txt"
        replay_file.write_text("metadata")

        with pytest.raises(
            ValueError, match=r"replay files must be crash \.bin artifacts"
        ):
            run(
                FuzzConfig(
                    target="ws://127.0.0.1:1",
                    replay=[replay_file],
                    log_dir=log_dir,
                )
            )

        assert not log_dir.exists()

    def test_programmatic_config_rejects_missing_scenario_early(self, tmp_path):
        log_dir = tmp_path / "crashes"

        with pytest.raises(ScenarioError, match="scenario file cannot be read"):
            run(
                FuzzConfig(
                    target="ws://127.0.0.1:1",
                    scenario=tmp_path / "missing.json",
                    iterations=1,
                    log_dir=log_dir,
                )
            )

        assert not log_dir.exists()

    def test_programmatic_binary_scenario_requires_text_mode_early(self, tmp_path):
        log_dir = tmp_path / "crashes"
        scenario_path = tmp_path / "scenario.json"
        scenario_path.write_text(
            json.dumps({"steps": [{"fuzz": {"template": {"id": "[FUZZ]"}}}]})
        )

        with pytest.raises(ValueError, match="use -m text"):
            run(
                FuzzConfig(
                    target="ws://127.0.0.1:1",
                    mode="binary",
                    scenario=scenario_path,
                    iterations=1,
                    log_dir=log_dir,
                )
            )

        assert not log_dir.exists()

    def test_programmatic_config_rejects_reuse_without_scenario(self, tmp_path):
        with pytest.raises(
            ValueError, match="--scenario-reuse-connection requires scenario"
        ):
            run(
                FuzzConfig(
                    target="ws://127.0.0.1:1",
                    scenario_reuse_connection=True,
                    iterations=1,
                    log_dir=tmp_path / "crashes",
                )
            )

    def test_fuzz_echo_server(self, echo_server, tmp_path, capsys):
        seeds_dir = Path(__file__).parent.parent / "seeds"
        config = FuzzConfig(
            target=echo_server,
            mode="binary",
            seeds_dir=seeds_dir,
            iterations=10,
            max_size=200,
            timeout=2.0,
            log_dir=tmp_path / "crashes",
            verbose=True,
        )
        run(config)
        out = capsys.readouterr().out
        assert "wsfuzz - WebSocket Fuzzer" in out
        assert "iterations: 10" in out

    def test_fuzz_text_mode(self, echo_server, tmp_path, capsys):
        seeds_dir = Path(__file__).parent.parent / "seeds"
        config = FuzzConfig(
            target=echo_server,
            mode="text",
            seeds_dir=seeds_dir,
            iterations=5,
            max_size=100,
            timeout=2.0,
            log_dir=tmp_path / "crashes",
            verbose=True,
        )
        run(config)
        out = capsys.readouterr().out
        assert "iterations: 5" in out

    def test_fuzz_connection_refused(self, tmp_path, capsys):
        config = FuzzConfig(
            target="ws://127.0.0.1:1",
            iterations=2,
            timeout=1.0,
            log_dir=tmp_path / "crashes",
        )
        run(config)
        out = capsys.readouterr().out
        assert "connection refused" in out
        assert "crashes:    0" in out

    def test_fuzz_connection_refused_gives_up(self, tmp_path, capsys):
        config = FuzzConfig(
            target="ws://127.0.0.1:1",
            iterations=0,
            timeout=1.0,
            log_dir=tmp_path / "crashes",
            max_retries=2,
        )
        run(config)
        out = capsys.readouterr().out
        assert "giving up after 2 consecutive failures" in out

    def test_fuzz_connection_refused_no_limit(self, tmp_path, capsys):
        config = FuzzConfig(
            target="ws://127.0.0.1:1",
            iterations=2,
            timeout=1.0,
            log_dir=tmp_path / "crashes",
            max_retries=0,
        )
        run(config)
        out = capsys.readouterr().out
        assert "giving up" not in out
        assert "crashes:    0" in out

    def test_fuzz_with_empty_seeds(self, echo_server, tmp_path, capsys):
        empty_seeds = tmp_path / "empty_seeds"
        empty_seeds.mkdir()
        config = FuzzConfig(
            target=echo_server,
            iterations=5,
            seeds_dir=empty_seeds,
            timeout=2.0,
            log_dir=tmp_path / "crashes",
            verbose=True,
        )
        run(config)
        out = capsys.readouterr().out
        assert "seeds:      1" in out
        assert "iterations: 5" in out

    def test_fuzz_max_size_truncation(self, echo_server, tmp_path, capsys):
        config = FuzzConfig(
            target=echo_server,
            iterations=5,
            max_size=10,
            timeout=2.0,
            log_dir=tmp_path / "crashes",
            verbose=True,
        )
        run(config)
        out = capsys.readouterr().out
        for line in out.splitlines():
            if line.startswith("[") and "ok" in line:
                size = int(line.split("(")[1].split("b")[0])
                assert size <= 10

    def test_fuzz_error_server_logs_crashes(self, echo_server, tmp_path, capsys):
        config = FuzzConfig(
            target=echo_server + "/error",
            iterations=3,
            timeout=2.0,
            log_dir=tmp_path / "crashes",
            crash_dedup=False,
        )
        run(config)
        crash_bins = list((tmp_path / "crashes").glob("crash_*.bin"))
        crash_txts = list((tmp_path / "crashes").glob("crash_*.txt"))
        assert len(crash_bins) == 3
        assert len(crash_txts) == 3

    def test_fuzz_error_server_deduplicates_crashes(
        self, echo_server, tmp_path, capsys
    ):
        config = FuzzConfig(
            target=echo_server + "/error",
            iterations=3,
            timeout=2.0,
            log_dir=tmp_path / "crashes",
        )
        run(config)
        out = capsys.readouterr().out
        crash_bins = list((tmp_path / "crashes").glob("crash_*.bin"))
        index = json.loads((tmp_path / "crashes" / "crash_index.json").read_text())

        assert len(crash_bins) == 1
        assert "crashes:    1" in out
        assert "duplicates: 2" in out
        assert next(iter(index["fingerprints"].values()))["count"] == 3


class TestReplay:
    def test_replay_crash_files(self, echo_server, tmp_path, capsys):
        """Replay mode should resend crash payloads and report results."""
        crash_dir = tmp_path / "crashes"
        crash_dir.mkdir()
        (crash_dir / "crash_0_1.bin").write_bytes(b"hello")
        (crash_dir / "crash_1_2.bin").write_bytes(b"world")

        config = FuzzConfig(
            target=echo_server,
            timeout=2.0,
            log_dir=tmp_path / "unused",
            replay=[crash_dir / "crash_0_1.bin", crash_dir / "crash_1_2.bin"],
        )
        run(config)
        out = capsys.readouterr().out
        assert "Replay Mode" in out
        assert "files:   2" in out
        assert "crash_0_1.bin" in out
        assert "crash_1_2.bin" in out

    def test_replay_reports_reproduced_behavior(self, tmp_path, monkeypatch, capsys):
        crash_file = tmp_path / "crash_0_1.bin"
        crash_file.write_bytes(b"payload")
        crash_file.with_suffix(".txt").write_text(
            "transport_mode: normal\nmessage_mode: text\nerror_type: boom\n"
        )

        async def fake_send_payload(uri, payload, mode, timeout, opts=None):
            return TransportResult(error="boom", error_type="boom", duration_ms=1.0)

        monkeypatch.setattr("wsfuzz.fuzzer.send_payload", fake_send_payload)

        run(
            FuzzConfig(
                target="ws://example.test/socket",
                timeout=1.0,
                log_dir=tmp_path / "unused",
                replay=[crash_file],
            )
        )

        out = capsys.readouterr().out
        assert "replay: reproduced" in out
        assert "replay summary: 1 reproduced, 0 changed, 0 unchecked" in out

    def test_replay_reports_changed_behavior(self, tmp_path, monkeypatch, capsys):
        crash_file = tmp_path / "crash_0_1.bin"
        crash_file.write_bytes(b"payload")
        crash_file.with_suffix(".txt").write_text(
            "transport_mode: normal\nmessage_mode: text\nerror_type: boom\n"
        )

        async def fake_send_payload(uri, payload, mode, timeout, opts=None):
            return TransportResult(response=b"ok", duration_ms=1.0)

        monkeypatch.setattr("wsfuzz.fuzzer.send_payload", fake_send_payload)

        run(
            FuzzConfig(
                target="ws://example.test/socket",
                timeout=1.0,
                log_dir=tmp_path / "unused",
                replay=[crash_file],
            )
        )

        out = capsys.readouterr().out
        assert "replay: changed" in out
        assert "error_type expected boom, got None" in out
        assert "replay summary: 0 reproduced, 1 changed, 0 unchecked" in out

    def test_replay_reports_response_hash_match(self, tmp_path, monkeypatch, capsys):
        crash_file = tmp_path / "crash_0_1.bin"
        crash_file.write_bytes(b"payload")
        response_hash = hashlib.sha256(b"ok").hexdigest()
        crash_file.with_suffix(".txt").write_text(
            f"transport_mode: normal\nmessage_mode: text\nresponse_sha256: {response_hash}\n"
        )

        async def fake_send_payload(uri, payload, mode, timeout, opts=None):
            return TransportResult(response=b"ok", duration_ms=1.0)

        monkeypatch.setattr("wsfuzz.fuzzer.send_payload", fake_send_payload)

        run(
            FuzzConfig(
                target="ws://example.test/socket",
                timeout=1.0,
                log_dir=tmp_path / "unused",
                replay=[crash_file],
            )
        )

        out = capsys.readouterr().out
        assert "replay: reproduced" in out

    def test_replay_reports_unexpected_error_from_response_baseline(
        self, tmp_path, monkeypatch, capsys
    ):
        crash_file = tmp_path / "crash_0_1.bin"
        crash_file.write_bytes(b"payload")
        response_hash = hashlib.sha256(b"ok").hexdigest()
        crash_file.with_suffix(".txt").write_text(
            "transport_mode: normal\n"
            "message_mode: text\n"
            "error_type: None\n"
            f"response_sha256: {response_hash}\n"
        )

        async def fake_send_payload(uri, payload, mode, timeout, opts=None):
            return TransportResult(error="boom", error_type="boom", duration_ms=1.0)

        monkeypatch.setattr("wsfuzz.fuzzer.send_payload", fake_send_payload)

        run(
            FuzzConfig(
                target="ws://example.test/socket",
                timeout=1.0,
                log_dir=tmp_path / "unused",
                replay=[crash_file],
            )
        )

        out = capsys.readouterr().out
        assert "replay: changed" in out
        assert "error_type expected None, got boom" in out
        assert "response_sha256 changed" in out

    def test_replay_reports_unchecked_without_metadata(
        self, tmp_path, monkeypatch, capsys
    ):
        crash_file = tmp_path / "crash_0_1.bin"
        crash_file.write_bytes(b"payload")

        async def fake_send_payload(uri, payload, mode, timeout, opts=None):
            return TransportResult(response=b"ok", duration_ms=1.0)

        monkeypatch.setattr("wsfuzz.fuzzer.send_payload", fake_send_payload)

        run(
            FuzzConfig(
                target="ws://example.test/socket",
                timeout=1.0,
                log_dir=tmp_path / "unused",
                replay=[crash_file],
            )
        )

        out = capsys.readouterr().out
        assert "replay: unchecked (no baseline metadata)" in out
        assert "replay summary: 0 reproduced, 0 changed, 1 unchecked" in out

    def test_replay_ignores_corrupt_metadata(self, tmp_path, monkeypatch, capsys):
        crash_file = tmp_path / "crash_0_1.bin"
        crash_file.write_bytes(b"payload")
        crash_file.with_suffix(".txt").write_bytes(b"\xff\xfe\xfd")

        async def fake_send_payload(uri, payload, mode, timeout, opts=None):
            return TransportResult(response=b"ok", duration_ms=1.0)

        monkeypatch.setattr("wsfuzz.fuzzer.send_payload", fake_send_payload)

        run(
            FuzzConfig(
                target="ws://example.test/socket",
                timeout=1.0,
                log_dir=tmp_path / "unused",
                replay=[crash_file],
            )
        )

        out = capsys.readouterr().out
        assert "replay: unchecked (no baseline metadata)" in out

    def test_replay_dir_expansion(self, echo_server, tmp_path, capsys):
        """--replay with a directory should find crash_*.bin files."""
        from wsfuzz.cli import main

        crash_dir = tmp_path / "crashes"
        crash_dir.mkdir()
        (crash_dir / "crash_0_1.bin").write_bytes(b"test")
        (crash_dir / "other.txt").write_bytes(b"ignored")

        # Test the CLI directory expansion logic directly
        import sys

        old_argv = sys.argv
        sys.argv = ["wsfuzz", "-t", echo_server, "--replay", str(crash_dir)]
        try:
            main()
        finally:
            sys.argv = old_argv
        out = capsys.readouterr().out
        assert "crash_0_1.bin" in out

    def test_replay_raw_resends_saved_frame_bytes(self, tmp_path, monkeypatch):
        crash_file = tmp_path / "crash_0_1.bin"
        crash_file.write_bytes(b"raw-frame-bytes")
        seen: dict[str, object] = {}

        async def fake_send_raw(
            target,
            frame,
            timeout,
            opts,
            *,
            fuzz_handshake=False,
            handshake_fuzz=None,
            ssl_context=None,
        ):
            seen["target"] = target
            seen["frame"] = frame
            seen["timeout"] = timeout
            seen["opts"] = opts
            seen["fuzz_handshake"] = fuzz_handshake
            seen["handshake_fuzz"] = handshake_fuzz
            return TransportResult(duration_ms=1.0)

        monkeypatch.setattr("wsfuzz.fuzzer.send_raw", fake_send_raw)

        run(
            FuzzConfig(
                target="ws://example.test/socket",
                timeout=2.0,
                log_dir=tmp_path / "unused",
                raw=True,
                replay=[crash_file],
            )
        )

        assert seen == {
            "target": "ws://example.test/socket",
            "frame": b"raw-frame-bytes",
            "timeout": 2.0,
            "opts": None,
            "fuzz_handshake": False,
            "handshake_fuzz": None,
        }

    def test_replay_raw_uses_saved_transport_mode_without_cli_flag(
        self, tmp_path, monkeypatch
    ):
        crash_file = tmp_path / "crash_0_1.bin"
        crash_file.write_bytes(b"raw-frame-bytes")
        crash_file.with_suffix(".txt").write_text("transport_mode: raw\n")
        seen: dict[str, object] = {}

        async def fake_send_raw(
            target,
            frame,
            timeout,
            opts,
            *,
            fuzz_handshake=False,
            handshake_fuzz=None,
            ssl_context=None,
        ):
            seen["target"] = target
            seen["frame"] = frame
            return TransportResult(duration_ms=1.0)

        async def fake_send_payload(uri, payload, mode, timeout, opts=None):
            raise AssertionError("raw replay should not use send_payload")

        monkeypatch.setattr("wsfuzz.fuzzer.send_raw", fake_send_raw)
        monkeypatch.setattr("wsfuzz.fuzzer.send_payload", fake_send_payload)

        run(
            FuzzConfig(
                target="ws://example.test/socket",
                timeout=2.0,
                log_dir=tmp_path / "unused",
                replay=[crash_file],
            )
        )

        assert seen == {
            "target": "ws://example.test/socket",
            "frame": b"raw-frame-bytes",
        }

    def test_replay_saved_normal_transport_mode_ignores_cli_scenario(
        self, tmp_path, monkeypatch
    ):
        crash_file = tmp_path / "crash_0_1.bin"
        crash_file.write_bytes(b"plain-payload")
        crash_file.with_suffix(".txt").write_text(
            "transport_mode: normal\nmessage_mode: text\n"
        )
        scenario_path = tmp_path / "scenario.json"
        scenario_path.write_text('{"steps":[{"fuzz":"[FUZZ]"}]}')
        seen: dict[str, object] = {}

        async def fake_send_payload(uri, payload, mode, timeout, opts=None):
            seen["uri"] = uri
            seen["payload"] = payload
            seen["mode"] = mode
            return TransportResult(duration_ms=1.0)

        async def fake_run_scenario_iteration(*args, **kwargs):
            raise AssertionError("normal replay should not use scenario mode")

        monkeypatch.setattr("wsfuzz.fuzzer.send_payload", fake_send_payload)
        monkeypatch.setattr(
            "wsfuzz.fuzzer.run_scenario_iteration", fake_run_scenario_iteration
        )

        run(
            FuzzConfig(
                target="ws://example.test/socket",
                timeout=2.0,
                log_dir=tmp_path / "unused",
                scenario=scenario_path,
                replay=[crash_file],
            )
        )

        assert seen == {
            "uri": "ws://example.test/socket",
            "payload": b"plain-payload",
            "mode": "text",
        }

    def test_replay_raw_uses_saved_handshake_fuzz_metadata(self, tmp_path, monkeypatch):
        crash_file = tmp_path / "crash_0_1.bin"
        crash_file.write_bytes(b"raw-frame-bytes")
        crash_file.with_suffix(".txt").write_text(
            "transport_mode: raw\n"
            "handshake_fuzz: true\n"
            "handshake_version: 99\n"
            "handshake_extension: permessage-deflate\n"
            "handshake_protocol: chat\n"
        )
        seen: dict[str, object] = {}

        async def fake_send_raw(
            target,
            frame,
            timeout,
            opts,
            *,
            fuzz_handshake=False,
            handshake_fuzz=None,
            ssl_context=None,
        ):
            seen["handshake_fuzz"] = handshake_fuzz
            return TransportResult(duration_ms=1.0)

        monkeypatch.setattr("wsfuzz.fuzzer.send_raw", fake_send_raw)

        run(
            FuzzConfig(
                target="ws://example.test/socket",
                timeout=2.0,
                log_dir=tmp_path / "unused",
                raw=True,
                replay=[crash_file],
            )
        )

        assert seen["handshake_fuzz"] == HandshakeFuzz(
            version="99",
            extension="permessage-deflate",
            protocol="chat",
        )


class TestRawCrashReplayability:
    def test_raw_mode_logs_frame_bytes(self, tmp_path, monkeypatch):
        seed_dir = tmp_path / "seeds"
        seed_dir.mkdir()
        (seed_dir / "seed.bin").write_bytes(b"seed")

        async def fake_mutate_async(seed_data, radamsa_path="radamsa", seed_num=None):
            return b"payload"

        async def fake_send_raw(
            uri,
            frame,
            timeout=5.0,
            opts=None,
            *,
            fuzz_handshake=False,
            handshake_fuzz=None,
            ssl_context=None,
        ):
            return TransportResult(
                error="boom",
                error_type="boom",
                duration_ms=1.0,
            )

        monkeypatch.setattr("wsfuzz.fuzzer.mutate_async", fake_mutate_async)
        monkeypatch.setattr("wsfuzz.fuzzer.build_frame", lambda *args, **kwargs: b"F")
        monkeypatch.setattr("wsfuzz.fuzzer.send_raw", fake_send_raw)

        run(
            FuzzConfig(
                target="ws://example.test/socket",
                seeds_dir=seed_dir,
                iterations=1,
                timeout=1.0,
                log_dir=tmp_path / "crashes",
                raw=True,
            )
        )

        crash_files = list((tmp_path / "crashes").glob("crash_*.bin"))
        assert len(crash_files) == 1
        assert crash_files[0].read_bytes() == b"F"

    def test_raw_handshake_fuzz_metadata_is_logged(self, tmp_path, monkeypatch):
        seed_dir = tmp_path / "seeds"
        seed_dir.mkdir()
        (seed_dir / "seed.bin").write_bytes(b"seed")

        async def fake_mutate_async(seed_data, radamsa_path="radamsa", seed_num=None):
            return b"payload"

        async def fake_send_raw(
            uri,
            frame,
            timeout=5.0,
            opts=None,
            *,
            fuzz_handshake=False,
            handshake_fuzz=None,
            ssl_context=None,
        ):
            return TransportResult(error="boom", error_type="boom", duration_ms=1.0)

        monkeypatch.setattr("wsfuzz.fuzzer.mutate_async", fake_mutate_async)
        monkeypatch.setattr("wsfuzz.fuzzer.build_frame", lambda *args, **kwargs: b"F")
        monkeypatch.setattr(
            "wsfuzz.fuzzer.make_handshake_fuzz",
            lambda enabled: (
                HandshakeFuzz(
                    version="99",
                    extension="permessage-deflate",
                    protocol="chat",
                )
                if enabled
                else None
            ),
        )
        monkeypatch.setattr("wsfuzz.fuzzer.send_raw", fake_send_raw)

        run(
            FuzzConfig(
                target="ws://example.test/socket",
                seeds_dir=seed_dir,
                iterations=1,
                timeout=1.0,
                log_dir=tmp_path / "crashes",
                raw=True,
                fuzz_handshake=True,
            )
        )

        crash_txt = next((tmp_path / "crashes").glob("crash_*.txt")).read_text()
        assert "transport_mode: raw" in crash_txt
        assert "message_mode: binary" in crash_txt
        assert "handshake_fuzz: true" in crash_txt
        assert "handshake_version: 99" in crash_txt
        assert "handshake_extension: permessage-deflate" in crash_txt
        assert "handshake_protocol: chat" in crash_txt


class TestConcurrency:
    def test_concurrent_overlaps_work(self, tmp_path, monkeypatch):
        """Concurrent fuzzing should overlap async work instead of serializing it."""
        active = 0
        max_active = 0

        async def fake_mutate_async(seed_data, radamsa_path="radamsa", seed_num=None):
            return b"x"

        async def fake_send_payload(uri, payload, mode, timeout, opts=None):
            nonlocal active, max_active
            active += 1
            max_active = max(max_active, active)
            try:
                await asyncio.sleep(0.05)
                return TransportResult(response=b"ok", duration_ms=50.0)
            finally:
                active -= 1

        monkeypatch.setattr("wsfuzz.fuzzer.mutate_async", fake_mutate_async)
        monkeypatch.setattr("wsfuzz.fuzzer.send_payload", fake_send_payload)

        def run_case(concurrency: int, log_dir: Path) -> tuple[float, int]:
            nonlocal max_active
            max_active = 0
            start = time.monotonic()
            run(
                FuzzConfig(
                    target="ws://example.test/socket",
                    iterations=10,
                    timeout=1.0,
                    log_dir=log_dir,
                    concurrency=concurrency,
                )
            )
            return (time.monotonic() - start) * 1000, max_active

        seq_ms, seq_max_active = run_case(1, tmp_path / "seq")
        con_ms, con_max_active = run_case(5, tmp_path / "con")

        assert seq_max_active == 1
        assert con_max_active > 1
        assert con_ms < seq_ms * 0.7, (
            f"concurrent={con_ms:.0f}ms, sequential={seq_ms:.0f}ms"
        )

    def test_concurrent_completes_all_iterations(self, echo_server, tmp_path, capsys):
        config = FuzzConfig(
            target=echo_server,
            iterations=15,
            timeout=2.0,
            log_dir=tmp_path / "crashes",
            concurrency=5,
            verbose=True,
        )
        run(config)
        out = capsys.readouterr().out
        assert "iterations: 15" in out

    def test_concurrent_error_server(self, echo_server, tmp_path, capsys):
        """Concurrent fuzzing against error server should log all crashes."""
        config = FuzzConfig(
            target=echo_server + "/error",
            iterations=10,
            timeout=2.0,
            log_dir=tmp_path / "crashes",
            concurrency=5,
            crash_dedup=False,
        )
        run(config)
        crash_files = list((tmp_path / "crashes").glob("crash_*.bin"))
        assert len(crash_files) == 10
