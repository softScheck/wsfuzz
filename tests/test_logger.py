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
        assert logger.crash_count == 5
        assert logger.error_types["SomeError"] == 5


class TestSummary:
    def test_summary_with_crashes(self, tmp_path):
        logger = CrashLogger(tmp_path)
        result = TransportResult(error="err", error_type="SomeError")
        logger.log_crash(0, b"a", result, 0, 1)
        logger.log_crash(1, b"b", result, 0, 2)

        summary = logger.summary(100)
        assert "iterations: 100" in summary
        assert "crashes:    2" in summary
        assert "SomeError: 2" in summary

    def test_summary_no_crashes(self, tmp_path):
        logger = CrashLogger(tmp_path)
        summary = logger.summary(50)
        assert "iterations: 50" in summary
        assert "crashes:    0" in summary

    def test_creates_log_dir(self, tmp_path):
        log_dir = tmp_path / "sub" / "dir"
        CrashLogger(log_dir)
        assert log_dir.exists()
