import asyncio
import hashlib
import json
import time
from pathlib import Path

import pytest

from wsfuzz.fuzzer import FuzzConfig, _compare_replay, run
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

    def test_fuzz_echo_server(self, echo_server, tmp_path):
        seeds_dir = Path(__file__).parent.parent / "seeds"
        config = FuzzConfig(
            target=echo_server,
            mode="binary",
            seeds_dir=seeds_dir,
            iterations=10,
            max_size=200,
            timeout=2.0,
            log_dir=tmp_path / "crashes",
        )
        run(config)
        # Echo server echoes everything — no crashes expected
        crash_bins = list((tmp_path / "crashes").glob("crash_*.bin"))
        assert len(crash_bins) == 0

    def test_fuzz_text_mode(self, echo_server, tmp_path):
        seeds_dir = Path(__file__).parent.parent / "seeds"
        config = FuzzConfig(
            target=echo_server,
            mode="text",
            seeds_dir=seeds_dir,
            iterations=5,
            max_size=100,
            timeout=2.0,
            log_dir=tmp_path / "crashes",
        )
        run(config)
        crash_bins = list((tmp_path / "crashes").glob("crash_*.bin"))
        assert len(crash_bins) == 0

    def test_fuzz_connection_refused(self, tmp_path):
        config = FuzzConfig(
            target="ws://127.0.0.1:1",
            iterations=2,
            timeout=1.0,
            log_dir=tmp_path / "crashes",
        )
        run(config)
        # Connection refused is filtered — no crash artifacts
        crash_bins = list((tmp_path / "crashes").glob("crash_*.bin"))
        assert len(crash_bins) == 0

    def test_fuzz_connection_refused_gives_up(self, tmp_path):
        config = FuzzConfig(
            target="ws://127.0.0.1:1",
            iterations=0,
            timeout=1.0,
            log_dir=tmp_path / "crashes",
            max_retries=2,
        )
        run(config)
        # With max_retries=2 and iterations=0 (infinite), fuzzer should
        # give up after 2 consecutive failures — no crash artifacts
        crash_bins = list((tmp_path / "crashes").glob("crash_*.bin"))
        assert len(crash_bins) == 0

    def test_fuzz_connection_refused_no_limit(self, tmp_path):
        config = FuzzConfig(
            target="ws://127.0.0.1:1",
            iterations=2,
            timeout=1.0,
            log_dir=tmp_path / "crashes",
            max_retries=0,
        )
        run(config)
        # max_retries=0 means no limit — runs all iterations even if all fail
        crash_bins = list((tmp_path / "crashes").glob("crash_*.bin"))
        assert len(crash_bins) == 0

    def test_fuzz_with_empty_seeds(self, echo_server, tmp_path):
        empty_seeds = tmp_path / "empty_seeds"
        empty_seeds.mkdir()
        config = FuzzConfig(
            target=echo_server,
            iterations=5,
            seeds_dir=empty_seeds,
            timeout=2.0,
            log_dir=tmp_path / "crashes",
        )
        run(config)
        # Empty seeds dir should use fallback seed; echo server → no crashes
        crash_bins = list((tmp_path / "crashes").glob("crash_*.bin"))
        assert len(crash_bins) == 0

    def test_fuzz_max_size_truncation(self, echo_server, tmp_path, monkeypatch):
        sent_sizes = []
        original_send = None

        import wsfuzz.fuzzer as fuzzer_mod

        original_send = fuzzer_mod.send_payload

        async def tracking_send(uri, payload, mode, timeout, opts=None):
            sent_sizes.append(len(payload))
            return await original_send(uri, payload, mode, timeout, opts)

        monkeypatch.setattr("wsfuzz.fuzzer.send_payload", tracking_send)

        config = FuzzConfig(
            target=echo_server,
            iterations=5,
            max_size=10,
            timeout=2.0,
            log_dir=tmp_path / "crashes",
        )
        run(config)
        assert len(sent_sizes) == 5
        assert all(s <= 10 for s in sent_sizes), (
            f"payloads exceeded max_size: {sent_sizes}"
        )

    def test_fuzz_error_server_logs_crashes(self, echo_server, tmp_path):
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

    def test_fuzz_error_server_deduplicates_crashes(self, echo_server, tmp_path):
        config = FuzzConfig(
            target=echo_server + "/error",
            iterations=3,
            timeout=2.0,
            log_dir=tmp_path / "crashes",
        )
        run(config)
        crash_bins = list((tmp_path / "crashes").glob("crash_*.bin"))
        index = json.loads((tmp_path / "crashes" / "crash_index.json").read_text())

        # Dedup: only 1 crash artifact, but index records all 3 observations
        assert len(crash_bins) == 1
        fingerprints = index["fingerprints"]
        assert len(fingerprints) == 1
        assert next(iter(fingerprints.values()))["count"] == 3


class TestReplay:
    def test_replay_crash_files(self, echo_server, tmp_path, monkeypatch):
        """Replay mode sends exact crash payloads."""
        crash_dir = tmp_path / "crashes"
        crash_dir.mkdir()
        (crash_dir / "crash_0_1.bin").write_bytes(b"hello")
        (crash_dir / "crash_1_2.bin").write_bytes(b"world")

        sent_payloads = []
        from wsfuzz.transport import send_payload

        async def tracking_send(uri, payload, mode, timeout, opts=None):
            sent_payloads.append(payload)
            return await send_payload(uri, payload, mode, timeout, opts)

        monkeypatch.setattr("wsfuzz.fuzzer.send_payload", tracking_send)

        config = FuzzConfig(
            target=echo_server,
            timeout=2.0,
            log_dir=tmp_path / "unused",
            replay=[crash_dir / "crash_0_1.bin", crash_dir / "crash_1_2.bin"],
        )
        run(config)
        assert len(sent_payloads) == 2
        assert set(sent_payloads) == {b"hello", b"world"}

    def test_compare_replay_reproduced_error_type(self):
        metadata = {"error_type": "boom"}
        result = TransportResult(error="boom", error_type="boom", duration_ms=1.0)
        comparison = _compare_replay(metadata, result)
        assert comparison.status == "reproduced"

    def test_compare_replay_changed_error_type(self):
        metadata = {"error_type": "boom"}
        result = TransportResult(response=b"ok", duration_ms=1.0)
        comparison = _compare_replay(metadata, result)
        assert comparison.status == "changed"
        assert "error_type expected boom, got None" in comparison.detail

    def test_compare_replay_response_hash_match(self):
        response_hash = hashlib.sha256(b"ok").hexdigest()
        metadata = {"response_sha256": response_hash}
        result = TransportResult(response=b"ok", duration_ms=1.0)
        comparison = _compare_replay(metadata, result)
        assert comparison.status == "reproduced"

    def test_compare_replay_response_hash_mismatch(self):
        response_hash = hashlib.sha256(b"ok").hexdigest()
        metadata = {"error_type": "None", "response_sha256": response_hash}
        result = TransportResult(error="boom", error_type="boom", duration_ms=1.0)
        comparison = _compare_replay(metadata, result)
        assert comparison.status == "changed"
        assert "error_type expected None, got boom" in comparison.detail
        assert "response_sha256 changed" in comparison.detail

    def test_compare_replay_unchecked_no_metadata(self):
        comparison = _compare_replay(
            {}, TransportResult(response=b"ok", duration_ms=1.0)
        )
        assert comparison.status == "unchecked"
        assert "no baseline metadata" in comparison.detail

    def test_compare_replay_close_code_match(self):
        metadata = {"close_code": "1011"}
        result = TransportResult(close_code=1011, duration_ms=1.0)
        comparison = _compare_replay(metadata, result)
        assert comparison.status == "reproduced"

    def test_compare_replay_close_code_mismatch(self):
        metadata = {"close_code": "1011"}
        result = TransportResult(close_code=1002, duration_ms=1.0)
        comparison = _compare_replay(metadata, result)
        assert comparison.status == "changed"
        assert "close_code expected 1011, got 1002" in comparison.detail

    def test_replay_dir_expansion(self, echo_server, tmp_path, monkeypatch):
        """--replay with a directory should find crash_*.bin files."""
        from wsfuzz.cli import main

        crash_dir = tmp_path / "crashes"
        crash_dir.mkdir()
        (crash_dir / "crash_0_1.bin").write_bytes(b"test")
        (crash_dir / "other.txt").write_bytes(b"ignored")

        sent_payloads = []
        from wsfuzz.transport import send_payload

        async def tracking_send(uri, payload, mode, timeout, opts=None):
            sent_payloads.append(payload)
            return await send_payload(uri, payload, mode, timeout, opts)

        monkeypatch.setattr("wsfuzz.fuzzer.send_payload", tracking_send)
        monkeypatch.setattr(
            "sys.argv",
            ["wsfuzz", "-t", echo_server, "--replay", str(crash_dir)],
        )
        main()
        # Only crash_0_1.bin should be replayed, not other.txt
        assert sent_payloads == [b"test"]

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

        crash_path = next((tmp_path / "crashes").glob("crash_*.txt"))
        meta = {}
        for line in crash_path.read_text().splitlines():
            key, sep, value = line.partition(":")
            if sep:
                meta[key.strip()] = value.lstrip()

        assert meta["transport_mode"] == "raw"
        assert meta["message_mode"] == "binary"
        assert meta["handshake_fuzz"] == "true"
        assert meta["handshake_version"] == "99"
        assert meta["handshake_extension"] == "permessage-deflate"
        assert meta["handshake_protocol"] == "chat"


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

    def test_concurrent_completes_all_iterations(self, echo_server, tmp_path):
        config = FuzzConfig(
            target=echo_server + "/error",
            iterations=15,
            timeout=2.0,
            log_dir=tmp_path / "crashes",
            concurrency=5,
            crash_dedup=False,
        )
        run(config)
        # All 15 iterations should complete and produce crash artifacts
        crash_bins = list((tmp_path / "crashes").glob("crash_*.bin"))
        assert len(crash_bins) == 15

    def test_concurrent_error_server(self, echo_server, tmp_path):
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
        crash_bins = list((tmp_path / "crashes").glob("crash_*.bin"))
        crash_txts = list((tmp_path / "crashes").glob("crash_*.txt"))
        assert len(crash_bins) == 10
        # Every .bin has matching .txt and all base names unique
        assert len(crash_txts) == 10
        assert len({p.stem for p in crash_bins}) == 10
