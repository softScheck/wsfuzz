import asyncio
import time
from pathlib import Path

from wsfuzz.fuzzer import FuzzConfig, run
from wsfuzz.raw import HandshakeFuzz
from wsfuzz.transport import TransportResult


class TestFuzzerIntegration:
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
        )
        run(config)
        crash_bins = list((tmp_path / "crashes").glob("crash_*.bin"))
        crash_txts = list((tmp_path / "crashes").glob("crash_*.txt"))
        assert len(crash_bins) == 3
        assert len(crash_txts) == 3


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

    def test_replay_raw_uses_saved_handshake_fuzz_metadata(self, tmp_path, monkeypatch):
        crash_file = tmp_path / "crash_0_1.bin"
        crash_file.write_bytes(b"raw-frame-bytes")
        crash_file.with_suffix(".txt").write_text(
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
        )
        run(config)
        crash_files = list((tmp_path / "crashes").glob("crash_*.bin"))
        assert len(crash_files) == 10
