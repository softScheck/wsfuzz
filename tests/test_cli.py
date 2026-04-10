import subprocess
import sys


class TestCli:
    def test_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "wsfuzz", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0
        assert "WebSocket fuzzer" in result.stdout
        assert "--target" in result.stdout
        assert "--tls-ca" in result.stdout
        assert "--insecure" in result.stdout

    def test_missing_target(self):
        result = subprocess.run(
            [sys.executable, "-m", "wsfuzz"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode != 0
        assert "required" in result.stderr

    def test_fuzz_handshake_requires_raw(self):
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "wsfuzz",
                "-t",
                "ws://127.0.0.1:1",
                "--fuzz-handshake",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode != 0
        assert "--fuzz-handshake requires --raw" in result.stderr
