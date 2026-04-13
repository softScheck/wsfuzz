import json
import subprocess
import sys

import pytest


def _run_cli(*args: str, timeout: int = 10) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "wsfuzz", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


class TestCli:
    def test_help(self):
        result = _run_cli("--help")
        assert result.returncode == 0
        assert "WebSocket fuzzer" in result.stdout
        assert "--target" in result.stdout
        assert "--tls-ca" in result.stdout
        assert "--insecure" in result.stdout
        assert "--scenario" in result.stdout
        assert "--scenario-reuse-connection" in result.stdout
        assert "--scenario-session-history-limit" in result.stdout
        assert "--no-dedupe" in result.stdout

    def test_missing_target(self):
        result = _run_cli()
        assert result.returncode != 0
        assert "required" in result.stderr

    @pytest.mark.parametrize(
        "target, error",
        [
            ("http://127.0.0.1:1", "target must be a ws:// or wss:// URL"),
            ("ws://127.0.0.1:1/\r\nX-Evil: 1", "target must not contain newlines"),
            ("ws://127.0.0.1:1/bad path", "target must not contain whitespace"),
            (
                "ws://127.0.0.1:1/socket#client-state",
                "target must not contain fragments",
            ),
            ("ws://:123/socket", "target must include a host"),
            ("ws://127.0.0.1:bad/socket", "target port must be between 1 and 65535"),
            ("ws://user:pass@127.0.0.1:1/socket", "target must not contain userinfo"),
            (
                "ws://127.0.0.1:1/socket\x0bcontrol",
                "target must not contain control characters",
            ),
        ],
    )
    def test_rejects_invalid_target(self, target, error):
        result = _run_cli("-t", target)
        assert result.returncode != 0
        assert error in result.stderr

    @pytest.mark.parametrize(
        "extra_args, error",
        [
            (["--fuzz-handshake"], "--fuzz-handshake requires --raw"),
            (
                ["--scenario-reuse-connection"],
                "--scenario-reuse-connection requires --scenario",
            ),
            (["--harness", "--raw"], "--raw is not supported with --harness"),
        ],
    )
    def test_rejects_incompatible_flags(self, extra_args, error):
        result = _run_cli("-t", "ws://127.0.0.1:1", *extra_args)
        assert result.returncode != 0
        assert error in result.stderr

    def test_harness_rejects_replay(self, tmp_path):
        crash_file = tmp_path / "crash_0_1.bin"
        crash_file.write_bytes(b"x")
        result = _run_cli(
            "-t", "ws://127.0.0.1:1", "--harness", "--replay", str(crash_file)
        )
        assert result.returncode != 0
        assert "--replay is not supported with --harness" in result.stderr

    @pytest.mark.parametrize(
        "extra_args, error",
        [
            (["--harness-template", "[FUZZ]"], "--harness-template requires --harness"),
            (
                ["--harness-template-format", "json"],
                "--harness-template-format requires --harness",
            ),
            (
                ["--harness", "--harness-template-format", "json"],
                "--harness-template-format requires --harness-template",
            ),
            (["--harness-port", "9999"], "--harness-port requires --harness"),
        ],
    )
    def test_harness_option_requires_parent(self, extra_args, error):
        result = _run_cli("-t", "ws://127.0.0.1:1", *extra_args)
        assert result.returncode != 0
        assert error in result.stderr

    def test_replay_requires_matching_files(self, tmp_path):
        missing = tmp_path / "missing.bin"
        result = _run_cli("-t", "ws://127.0.0.1:1", "--replay", str(missing))
        assert result.returncode != 0
        assert "--replay did not match any crash .bin files" in result.stderr

    def test_replay_rejects_non_bin_files(self, tmp_path):
        metadata_file = tmp_path / "crash_0_1.txt"
        metadata_file.write_text("error_type: boom\n")
        result = _run_cli("-t", "ws://127.0.0.1:1", "--replay", str(metadata_file))
        assert result.returncode != 0
        assert "--replay files must be crash .bin artifacts" in result.stderr

    @pytest.mark.parametrize("timeout_value", ["0", "nan", "inf"])
    def test_rejects_invalid_timeout(self, timeout_value):
        result = _run_cli("-t", "ws://127.0.0.1:1", "--timeout", timeout_value)
        assert result.returncode != 0
        assert "--timeout must be positive" in result.stderr

    def test_rejects_invalid_harness_port(self):
        result = _run_cli(
            "-t", "ws://127.0.0.1:1", "--harness", "--harness-port", "70000"
        )
        assert result.returncode != 0
        assert "--harness-port must be between 1 and 65535" in result.stderr

    @pytest.mark.parametrize(
        "header_arg, error",
        [
            ("Authorization", "--header must use K:V format"),
            (": token", "--header must use K:V format"),
            ("Bad Header: value", "--header name must be a valid HTTP token"),
            ("X-Test : value", "--header name must be a valid HTTP token"),
            ("X-Test: ok\x0bbad", "--header must not contain control characters"),
        ],
    )
    def test_header_validation(self, header_arg, error):
        result = _run_cli("-t", "ws://127.0.0.1:1", "-H", header_arg)
        assert result.returncode != 0
        assert error in result.stderr

    @pytest.mark.parametrize(
        "origin, error",
        [
            ("https://example.test\r\nX-Evil: 1", "--origin must not contain newlines"),
            (
                "https://example.test\x0bbad",
                "--origin must not contain control characters",
            ),
        ],
    )
    def test_origin_validation(self, origin, error):
        result = _run_cli("-t", "ws://127.0.0.1:1", "--origin", origin)
        assert result.returncode != 0
        assert error in result.stderr

    def test_header_allows_empty_value(self, monkeypatch):
        from wsfuzz.cli import main

        seen: dict[str, object] = {}

        def fake_run(config) -> None:
            seen["headers"] = config.headers

        monkeypatch.setattr("wsfuzz.cli.run", fake_run)

        old_argv = sys.argv
        sys.argv = ["wsfuzz", "-t", "ws://127.0.0.1:1", "-H", "X-Empty:"]
        try:
            main()
        finally:
            sys.argv = old_argv

        assert seen == {"headers": {"X-Empty": ""}}

    def test_scenario_defaults_to_text_mode(self, tmp_path):
        scenario_path = tmp_path / "scenario.json"
        scenario_path.write_text(json.dumps({"steps": [{"fuzz": "[FUZZ]"}]}))

        result = _run_cli(
            "-t", "ws://127.0.0.1:1", "--scenario", str(scenario_path), "-n", "1"
        )
        assert "mode:       text" in result.stdout

    def test_binary_structured_scenario_requires_text_mode(self, tmp_path):
        scenario_path = tmp_path / "scenario.json"
        scenario_path.write_text(
            json.dumps({"steps": [{"fuzz": {"template": {"id": "[FUZZ]"}}}]})
        )
        result = _run_cli(
            "-t", "ws://127.0.0.1:1", "--scenario", str(scenario_path), "-m", "binary"
        )
        assert result.returncode != 0
        assert "use -m text for structured JSON/text scenarios" in result.stderr

    def test_invalid_scenario_reports_cli_error(self, tmp_path):
        scenario_path = tmp_path / "scenario.json"
        scenario_path.write_text("{not-json")

        for extra_args in ([], ["-m", "binary"]):
            result = _run_cli(
                "-t", "ws://127.0.0.1:1", "--scenario", str(scenario_path), *extra_args
            )
            assert result.returncode != 0
            assert "scenario file is not valid JSON" in result.stderr
            assert "Traceback" not in result.stderr

    def test_missing_scenario_reports_cli_error(self, tmp_path):
        scenario_path = tmp_path / "missing.json"

        for extra_args in ([], ["-m", "binary"]):
            result = _run_cli(
                "-t", "ws://127.0.0.1:1", "--scenario", str(scenario_path), *extra_args
            )
            assert result.returncode != 0
            assert "scenario file cannot be read" in result.stderr
            assert "Traceback" not in result.stderr

    def test_binary_scenario_allows_json_setup_with_raw_fuzz_step(self, tmp_path):
        scenario_path = tmp_path / "scenario.json"
        scenario_path.write_text(
            json.dumps(
                {
                    "setup": [{"send": {"op": "hello"}}],
                    "steps": [{"fuzz": "[FUZZ]"}],
                }
            )
        )
        result = _run_cli(
            "-t",
            "ws://127.0.0.1:1",
            "--scenario",
            str(scenario_path),
            "-m",
            "binary",
            "-n",
            "1",
            "--max-retries",
            "1",
        )
        assert result.returncode == 0
        assert "use -m text for structured JSON/text scenarios" not in result.stderr

    def test_harness_defaults_to_text_mode(self, monkeypatch):
        from wsfuzz.cli import main

        seen: dict[str, object] = {}

        async def fake_run_harness(
            target: str,
            *,
            mode: str = "text",
            timeout: float = 5.0,
            opts=None,
            template=None,
            template_format: str = "raw",
            listen_host: str = "127.0.0.1",
            listen_port: int = 8765,
        ) -> None:
            seen["target"] = target
            seen["mode"] = mode
            seen["template_format"] = template_format

        monkeypatch.setattr("wsfuzz.cli.run_harness", fake_run_harness)

        old_argv = sys.argv
        sys.argv = ["wsfuzz", "-t", "ws://127.0.0.1:1", "--harness"]
        try:
            main()
        finally:
            sys.argv = old_argv

        assert seen == {
            "target": "ws://127.0.0.1:1",
            "mode": "text",
            "template_format": "raw",
        }

    def test_harness_template_format_json(self, monkeypatch):
        from wsfuzz.cli import main

        seen: dict[str, object] = {}

        async def fake_run_harness(
            target: str,
            *,
            mode: str = "text",
            timeout: float = 5.0,
            opts=None,
            template=None,
            template_format: str = "raw",
            listen_host: str = "127.0.0.1",
            listen_port: int = 8765,
        ) -> None:
            seen["template"] = template
            seen["template_format"] = template_format

        monkeypatch.setattr("wsfuzz.cli.run_harness", fake_run_harness)

        old_argv = sys.argv
        sys.argv = [
            "wsfuzz",
            "-t",
            "ws://127.0.0.1:1",
            "--harness",
            "--harness-template",
            '{"id":"[FUZZ]"}',
            "--harness-template-format",
            "json",
        ]
        try:
            main()
        finally:
            sys.argv = old_argv

        assert seen == {
            "template": '{"id":"[FUZZ]"}',
            "template_format": "json",
        }

    def test_harness_option_validation_reports_cli_error(self, monkeypatch, capsys):
        from wsfuzz.cli import main

        def fake_make_connect_opts(*args, **kwargs):
            raise ValueError("bad harness opts")

        monkeypatch.setattr("wsfuzz.cli.make_connect_opts", fake_make_connect_opts)

        old_argv = sys.argv
        sys.argv = ["wsfuzz", "-t", "ws://127.0.0.1:1", "--harness"]
        try:
            try:
                main()
            except SystemExit as exc:
                assert exc.code == 2
        finally:
            sys.argv = old_argv

        assert "bad harness opts" in capsys.readouterr().err

    def test_no_dedupe_sets_config(self, monkeypatch):
        from wsfuzz.cli import main

        seen: dict[str, object] = {}

        def fake_run(config) -> None:
            seen["crash_dedup"] = config.crash_dedup

        monkeypatch.setattr("wsfuzz.cli.run", fake_run)

        old_argv = sys.argv
        sys.argv = ["wsfuzz", "-t", "ws://127.0.0.1:1", "--no-dedupe"]
        try:
            main()
        finally:
            sys.argv = old_argv

        assert seen == {"crash_dedup": False}
