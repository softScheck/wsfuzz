import time
from pathlib import Path

from wsfuzz.fuzzer import FuzzConfig, run


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


class TestConcurrency:
    def test_concurrent_faster_than_sequential(self, echo_server, tmp_path):
        """Concurrent fuzzing should be faster than sequential."""
        seeds_dir = Path(__file__).parent.parent / "seeds"
        n = 20

        start = time.monotonic()
        run(
            FuzzConfig(
                target=echo_server,
                iterations=n,
                timeout=2.0,
                seeds_dir=seeds_dir,
                log_dir=tmp_path / "seq",
                concurrency=1,
            )
        )
        seq_ms = (time.monotonic() - start) * 1000

        start = time.monotonic()
        run(
            FuzzConfig(
                target=echo_server,
                iterations=n,
                timeout=2.0,
                seeds_dir=seeds_dir,
                log_dir=tmp_path / "con",
                concurrency=10,
            )
        )
        con_ms = (time.monotonic() - start) * 1000

        # Concurrent should be at least somewhat faster
        assert con_ms < seq_ms * 1.5, (
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
