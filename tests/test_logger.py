import json
from pathlib import Path

from wsfuzz.logger import CrashLogger
from wsfuzz.transport import TransportResult


class TestIsInteresting:
    def test_no_error(self):
        logger = CrashLogger(Path("/tmp/unused"))
        assert logger.is_interesting(TransportResult(response=b"ok")) is False

    def test_timeout(self):
        logger = CrashLogger(Path("/tmp/unused"))
        assert (
            logger.is_interesting(
                TransportResult(error="timeout", error_type="timeout")
            )
            is False
        )

    def test_connection_refused(self):
        logger = CrashLogger(Path("/tmp/unused"))
        r = TransportResult(
            error="refused", error_type="connection_refused", connection_refused=True
        )
        assert logger.is_interesting(r) is False

    def test_transport_config_error(self):
        logger = CrashLogger(Path("/tmp/unused"))
        r = TransportResult(error="bad TLS config", error_type="transport_config")
        assert logger.is_interesting(r) is False

    def test_connection_reset(self):
        logger = CrashLogger(Path("/tmp/unused"))
        assert (
            logger.is_interesting(
                TransportResult(error="reset", error_type="connection_reset")
            )
            is True
        )

    def test_generic_error(self):
        logger = CrashLogger(Path("/tmp/unused"))
        assert (
            logger.is_interesting(
                TransportResult(error="broke", error_type="RuntimeError")
            )
            is True
        )

    def test_close_code_error(self):
        logger = CrashLogger(Path("/tmp/unused"))
        r = TransportResult(
            error="close code 1011: internal error",
            error_type="close_1011",
            close_code=1011,
        )
        assert logger.is_interesting(r) is True


class TestLogCrash:
    def test_creates_files(self, tmp_path):
        logger = CrashLogger(tmp_path)
        result = TransportResult(
            error="connection reset", error_type="connection_reset", duration_ms=42.5
        )
        logger.log_crash(
            iteration=7,
            payload=b"\xde\xad\xbe\xef",
            result=result,
            seed_index=2,
            radamsa_seed=12345,
        )

        assert logger.crash_count == 1
        assert logger.error_types["connection_reset"] == 1

        bin_files = list(tmp_path.glob("crash_7_*.bin"))
        txt_files = list(tmp_path.glob("crash_7_*.txt"))
        assert len(bin_files) == 1
        assert len(txt_files) == 1
        assert bin_files[0].read_bytes() == b"\xde\xad\xbe\xef"

        txt = txt_files[0].read_text()
        assert "iteration: 7" in txt
        assert "radamsa_seed: 12345" in txt
        assert "connection_reset" in txt
        assert "close_code: None" in txt
        assert "response_sha256:" in txt

    def test_null_bytes_in_payload(self, tmp_path):
        logger = CrashLogger(tmp_path)
        payload = b"\x00" * 50
        result = TransportResult(error="err", error_type="SomeError")
        logger.log_crash(0, payload, result, 0, 1)

        bin_files = list(tmp_path.glob("crash_0_*.bin"))
        assert bin_files[0].read_bytes() == payload

    def test_multiple_crashes_same_type(self, tmp_path):
        logger = CrashLogger(tmp_path)
        result = TransportResult(error="err", error_type="SomeError")
        for i in range(5):
            logger.log_crash(i, b"x", result, 0, i)
        assert logger.crash_count == 1
        assert logger.duplicate_count == 4
        assert logger.error_types["SomeError"] == 1

    def test_deduplicates_same_crash_fingerprint(self, tmp_path):
        logger = CrashLogger(tmp_path)
        result = TransportResult(error="err", error_type="SomeError")

        first = logger.log_crash(0, b"first", result, 0, 1)
        second = logger.log_crash(1, b"second", result, 0, 2)

        assert first.saved is True
        assert first.duplicate_count == 1
        assert second.saved is False
        assert second.fingerprint == first.fingerprint
        assert second.duplicate_count == 2
        assert second.base_name == first.base_name
        assert len(list(tmp_path.glob("crash_*.bin"))) == 1
        index = json.loads((tmp_path / "crash_index.json").read_text())
        assert index["fingerprints"][first.fingerprint]["count"] == 2

    def test_stale_dedupe_index_does_not_suppress_artifact(self, tmp_path):
        logger = CrashLogger(tmp_path)
        result = TransportResult(error="err", error_type="SomeError")
        first = logger.log_crash(0, b"first", result, 0, 1)
        assert first.saved is True
        for artifact in tmp_path.glob("crash_*.bin"):
            artifact.unlink()

        logger = CrashLogger(tmp_path)
        second = logger.log_crash(1, b"second", result, 0, 2)

        assert second.saved is True
        assert second.duplicate_count == 1
        assert len(list(tmp_path.glob("crash_*.bin"))) == 1
        assert next(tmp_path.glob("crash_*.bin")).read_bytes() == b"second"

    def test_stale_dedupe_index_without_metadata_does_not_suppress_artifact(
        self, tmp_path
    ):
        logger = CrashLogger(tmp_path)
        result = TransportResult(error="err", error_type="SomeError")
        first = logger.log_crash(0, b"first", result, 0, 1)
        assert first.saved is True
        for artifact in tmp_path.glob("crash_*.txt"):
            artifact.unlink()

        logger = CrashLogger(tmp_path)
        second = logger.log_crash(1, b"second", result, 0, 2)

        assert second.saved is True
        assert second.duplicate_count == 1
        assert len(list(tmp_path.glob("crash_*.bin"))) == 2
        assert len(list(tmp_path.glob("crash_*.txt"))) == 1

    def test_no_dedupe_saves_every_matching_crash(self, tmp_path, monkeypatch):
        logger = CrashLogger(tmp_path, dedupe=False)
        result = TransportResult(error="err", error_type="SomeError")
        monkeypatch.setattr("wsfuzz.logger.time.time_ns", lambda: 123)

        first = logger.log_crash(0, b"first", result, 0, 1)
        second = logger.log_crash(0, b"second", result, 0, 2)

        assert first.saved is True
        assert second.saved is True
        assert logger.crash_count == 2
        assert logger.duplicate_count == 0
        assert len(list(tmp_path.glob("crash_*.bin"))) == 2

    def test_corrupt_index_is_ignored(self, tmp_path):
        (tmp_path / "crash_index.json").write_bytes(b"\xff\xfe\xfd")

        logger = CrashLogger(tmp_path)
        result = TransportResult(error="err", error_type="SomeError")
        logged = logger.log_crash(0, b"x", result, 0, 1)

        assert logged.saved is True
        assert logger.crash_count == 1

    def test_invalid_index_entries_are_ignored(self, tmp_path):
        (tmp_path / "crash_0.bin").write_bytes(b"x")
        (tmp_path / "crash_0.txt").write_text("error_type: SomeError\n")
        (tmp_path / "outside.bin").write_bytes(b"x")
        (tmp_path / "outside.txt").write_text("error_type: SomeError\n")
        (tmp_path / "crash_index.json").write_text(
            json.dumps(
                {
                    "fingerprints": {
                        "negative": {
                            "count": -1,
                            "first": "crash_0",
                            "error_type": "SomeError",
                        },
                        "boolean": {
                            "count": True,
                            "first": "crash_0",
                            "error_type": "SomeError",
                        },
                        "pathlike": {
                            "count": 1,
                            "first": "../outside",
                            "error_type": "SomeError",
                        },
                        "windows_pathlike": {
                            "count": 1,
                            "first": "..\\outside",
                            "error_type": "SomeError",
                        },
                        "empty": {
                            "count": 1,
                            "first": "",
                            "error_type": "SomeError",
                        },
                    }
                }
            )
        )

        logger = CrashLogger(tmp_path)

        assert logger._fingerprints == {}

    def test_index_write_replaces_atomically_and_cleans_temp(self, tmp_path):
        logger = CrashLogger(tmp_path)
        result = TransportResult(error="err", error_type="SomeError")

        logged = logger.log_crash(0, b"x", result, 0, 1)

        index = json.loads((tmp_path / "crash_index.json").read_text())
        assert logged.fingerprint in index["fingerprints"]
        assert list(tmp_path.glob(".crash_index.json.*.tmp")) == []

    def test_fingerprint_includes_scenario_fuzz_point(self, tmp_path):
        logger = CrashLogger(tmp_path)
        result = TransportResult(error="err", error_type="SomeError")

        first = logger.log_crash(
            0,
            b"first",
            result,
            0,
            1,
            extra_metadata={"scenario_fuzz_ordinal": "0"},
        )
        second = logger.log_crash(
            1,
            b"second",
            result,
            0,
            2,
            extra_metadata={"scenario_fuzz_ordinal": "1"},
        )

        assert first.saved is True
        assert second.saved is True
        assert first.fingerprint != second.fingerprint
        assert len(list(tmp_path.glob("crash_*.bin"))) == 2

    def test_writes_extra_metadata(self, tmp_path):
        logger = CrashLogger(tmp_path)
        result = TransportResult(error="err", error_type="SomeError")
        logger.log_crash(
            0,
            b"x",
            result,
            0,
            1,
            extra_metadata={
                "handshake_fuzz": "true",
                "handshake_version": "99",
                "handshake_extension": "",
            },
        )

        txt = next(tmp_path.glob("crash_0_*.txt")).read_text()
        assert "handshake_fuzz: true" in txt
        assert "handshake_version: 99" in txt

    def test_metadata_values_escape_newlines(self, tmp_path):
        logger = CrashLogger(tmp_path)
        result = TransportResult(
            error="boom\ntransport_mode: raw",
            error_type="SomeError",
        )
        logger.log_crash(
            0,
            b"x",
            result,
            0,
            1,
            extra_metadata={
                "scenario_fuzz_name": "name\nmessage_mode: binary",
            },
        )

        lines = next(tmp_path.glob("crash_0_*.txt")).read_text().splitlines()
        assert "error: boom\\ntransport_mode: raw" in lines
        assert "scenario_fuzz_name: name\\nmessage_mode: binary" in lines
        assert "transport_mode: raw" not in lines
        assert "message_mode: binary" not in lines

    def test_writes_extra_artifacts(self, tmp_path):
        logger = CrashLogger(tmp_path)
        result = TransportResult(error="err", error_type="SomeError")
        logger.log_crash(
            0,
            b"x",
            result,
            0,
            1,
            extra_artifacts={".scenario.json": '{"steps":[]}'},
        )

        artifact = next(tmp_path.glob("crash_0_*.scenario.json"))
        assert artifact.read_text() == '{"steps":[]}'

    def test_same_iteration_crashes_do_not_overwrite(self, tmp_path, monkeypatch):
        logger = CrashLogger(tmp_path, dedupe=False)
        result = TransportResult(error="err", error_type="SomeError")
        monkeypatch.setattr("wsfuzz.logger.time.time_ns", lambda: 123)

        logger.log_crash(0, b"first", result, 0, 1)
        logger.log_crash(0, b"second", result, 0, 2)

        payloads = sorted(path.read_bytes() for path in tmp_path.glob("crash_0_*.bin"))
        metadata = sorted(path.read_text() for path in tmp_path.glob("crash_0_*.txt"))

        assert payloads == [b"first", b"second"]
        assert len(metadata) == 2
        assert any("radamsa_seed: 1" in text for text in metadata)
        assert any("radamsa_seed: 2" in text for text in metadata)


class TestSummary:
    def test_summary_with_crashes(self, tmp_path):
        logger = CrashLogger(tmp_path)
        result = TransportResult(error="err", error_type="SomeError")
        logger.log_crash(0, b"a", result, 0, 1)
        logger.log_crash(1, b"b", result, 0, 2)

        summary = logger.summary(100)
        assert "iterations: 100" in summary
        assert "crashes:    1" in summary
        assert "duplicates: 1" in summary
        assert "SomeError: 1" in summary

    def test_summary_no_crashes(self, tmp_path):
        logger = CrashLogger(tmp_path)
        summary = logger.summary(50)
        assert "iterations: 50" in summary
        assert "crashes:    0" in summary

    def test_creates_log_dir(self, tmp_path):
        log_dir = tmp_path / "sub" / "dir"
        CrashLogger(log_dir)
        assert log_dir.exists()
