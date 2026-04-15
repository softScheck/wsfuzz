import asyncio
import json
import ssl
import time
from email.message import Message
from io import BytesIO
from pathlib import Path
from urllib.error import HTTPError

import pytest

from tests.echo_server import reuse_connection_count
from wsfuzz.fuzzer import FuzzConfig, run
from wsfuzz.scenario import (
    ScenarioError,
    ScenarioSession,
    _run_pre_http,
    load_scenario,
    run_scenario_iteration,
    select_fuzz_step,
)
from wsfuzz.transport import ConnectOpts


def _write_scenario(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload))
    return path


class TestScenarioRunner:
    def test_load_scenario_rejects_invalid_json(self, tmp_path):
        scenario_path = tmp_path / "scenario.json"
        scenario_path.write_text("{not-json")

        with pytest.raises(ScenarioError, match="scenario file is not valid JSON"):
            load_scenario(scenario_path)

    @pytest.mark.parametrize("connect", [[], "", None])
    def test_load_scenario_rejects_non_object_connect(self, tmp_path, connect):
        scenario_path = _write_scenario(
            tmp_path / "scenario.json",
            {
                "connect": connect,
                "steps": [{"fuzz": "[FUZZ]"}],
            },
        )

        with pytest.raises(ScenarioError, match="scenario connect must be an object"):
            load_scenario(scenario_path)

    @pytest.mark.parametrize(
        ("payload", "message"),
        [
            (
                {
                    "connect": {
                        "url": "ws://example.test/a",
                        "path": "/b",
                    },
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                "scenario connect cannot define both url and path",
            ),
            (
                {
                    "connect": {"path": "ws://example.test/socket"},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                "scenario connect.path must be a path, not a URL",
            ),
            (
                {
                    "connect": {"url": "http://example.test/socket"},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                r"scenario connect.url must be a ws:// or wss:// URL",
            ),
            (
                {
                    "connect": {"url": "ws://:123/socket"},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                r"scenario connect.url must include a host",
            ),
            (
                {
                    "connect": {"url": "ws://example.test:bad/socket"},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                r"scenario connect.url port must be between 1 and 65535",
            ),
            (
                {
                    "connect": {"url": "ws://user:pass@example.test/socket"},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                r"scenario connect.url must not contain userinfo",
            ),
            (
                {
                    "connect": {"url": "ws://example.test/socket\r\nX-Evil: 1"},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                r"scenario connect.url must not contain newlines",
            ),
            (
                {
                    "connect": {"url": "ws://example.test/bad path"},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                r"scenario connect.url must not contain whitespace",
            ),
            (
                {
                    "connect": {"url": "ws://example.test/socket\x0bcontrol"},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                r"scenario connect.url must not contain control characters",
            ),
            (
                {
                    "connect": {"url": "ws://example.test/socket#client-state"},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                r"scenario connect.url must not contain fragments",
            ),
            (
                {
                    "connect": {"path": "/socket\r\nX-Evil: 1"},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                r"scenario connect.path must not contain newlines",
            ),
            (
                {
                    "connect": {"path": "/bad path"},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                r"scenario connect.path must not contain whitespace",
            ),
            (
                {
                    "connect": {"path": "/socket\x0bcontrol"},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                r"scenario connect.path must not contain control characters",
            ),
            (
                {
                    "connect": {"path": "/socket#client-state"},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                r"scenario connect.path must not contain fragments",
            ),
            (
                {
                    "connect": {"origin": "https://example.test\r\nX-Evil: 1"},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                r"scenario connect.origin must not contain newlines",
            ),
            (
                {
                    "connect": {"origin": "https://example.test\x0bbad"},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                r"scenario connect.origin must not contain control characters",
            ),
            (
                {
                    "connect": {"hederrs": {"Authorization": "Bearer token"}},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                "unsupported scenario connect key: hederrs",
            ),
            (
                {
                    "pre_http": None,
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                "scenario pre_http must be an object",
            ),
            (
                {
                    "pre_http": {},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                "scenario pre_http missing required key: url",
            ),
            (
                {
                    "pre_http": {"url": "ws://example.test/auth"},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                r"scenario pre_http.url must be an http:// or https:// URL",
            ),
            (
                {
                    "pre_http": {"url": "https://:443/auth"},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                r"scenario pre_http.url must include a host",
            ),
            (
                {
                    "pre_http": {"url": "https://example.test:bad/auth"},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                r"scenario pre_http.url port must be between 1 and 65535",
            ),
            (
                {
                    "pre_http": {"url": "https://user:pass@example.test/auth"},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                r"scenario pre_http.url must not contain userinfo",
            ),
            (
                {
                    "pre_http": {"url": "https://example.test/auth\r\nX-Evil: 1"},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                r"scenario pre_http.url must not contain newlines",
            ),
            (
                {
                    "pre_http": {"url": "https://example.test/bad path"},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                r"scenario pre_http.url must not contain whitespace",
            ),
            (
                {
                    "pre_http": {"url": "https://example.test/auth\x0bcontrol"},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                r"scenario pre_http.url must not contain control characters",
            ),
            (
                {
                    "pre_http": {"url": "https://example.test/auth#client-state"},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                r"scenario pre_http.url must not contain fragments",
            ),
            (
                {
                    "pre_http": {"url": "https://example.test", "method": "BAD METHOD"},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                "scenario pre_http.method must be a valid HTTP token",
            ),
            (
                {
                    "pre_http": {"url": "https://example.test", "captuer": {}},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                "unsupported scenario pre_http key: captuer",
            ),
            (
                {
                    "pre_http": {
                        "url": "https://example.test",
                        "capture": {"json": {}, "regex": {}},
                    },
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                "unsupported scenario pre_http.capture key: regex",
            ),
            (
                {
                    "connect": {"headers": []},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                "scenario connect.headers must be an object",
            ),
            (
                {
                    "connect": {"headers": {"": "token"}},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                "scenario connect.headers names must not be empty",
            ),
            (
                {
                    "connect": {"headers": {"Bad Header": "token"}},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                "scenario connect.headers names must be valid HTTP tokens",
            ),
            (
                {
                    "connect": {"headers": {" X-Test": "token"}},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                "scenario connect.headers names must be valid HTTP tokens",
            ),
            (
                {
                    "connect": {"headers": {"X-Test": "ok\r\nX-Evil: 1"}},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                "scenario connect.headers must not contain newlines",
            ),
            (
                {
                    "connect": {"headers": {"X-Test": "ok\x0bbad"}},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                "scenario connect.headers must not contain control characters",
            ),
            (
                {
                    "pre_http": {"url": "https://example.test", "headers": ""},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                "scenario pre_http.headers must be an object",
            ),
            (
                {
                    "pre_http": {
                        "url": "https://example.test",
                        "headers": {"Bad Header": "1"},
                    },
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                "scenario pre_http.headers names must be valid HTTP tokens",
            ),
            (
                {
                    "pre_http": {
                        "url": "https://example.test",
                        "headers": {" X-Test": "1"},
                    },
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                "scenario pre_http.headers names must be valid HTTP tokens",
            ),
            (
                {
                    "pre_http": {
                        "url": "https://example.test",
                        "headers": {"X-Test\r\nX-Evil": "1"},
                    },
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                "scenario pre_http.headers must not contain newlines",
            ),
            (
                {
                    "pre_http": {
                        "url": "https://example.test",
                        "headers": {"X-Test": "ok\x0bbad"},
                    },
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                "scenario pre_http.headers must not contain control characters",
            ),
            (
                {
                    "pre_http": {"url": "https://example.test", "capture": []},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                "scenario pre_http.capture must be an object",
            ),
            (
                {
                    "pre_http": {
                        "url": "https://example.test",
                        "expect_status": "not-a-status",
                    },
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                "scenario pre_http.expect_status must be an integer",
            ),
            (
                {
                    "pre_http": {
                        "url": "https://example.test",
                        "expect_status": 200.5,
                    },
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                "scenario pre_http.expect_status must be an integer",
            ),
            (
                {
                    "pre_http": {
                        "url": "https://example.test",
                        "expect_status": 99,
                    },
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                "scenario pre_http.expect_status must be between 100 and 599",
            ),
            (
                {
                    "setup": [{"fuzz": "[FUZZ]"}],
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
                "scenario setup cannot contain fuzz steps",
            ),
            (
                {
                    "steps": [{"fuzz": {"name": "missing-template"}}],
                },
                r"scenario fuzz step requires template",
            ),
            (
                {
                    "steps": [{"fuzz": {"name": 123, "template": "[FUZZ]"}}],
                },
                r"scenario fuzz step name must be a string",
            ),
            (
                {
                    "steps": [{"sleep": -1}, {"fuzz": "[FUZZ]"}],
                },
                r"scenario steps\[0\].sleep must be non-negative",
            ),
            (
                {
                    "steps": [{"sleep": "nan"}, {"fuzz": "[FUZZ]"}],
                },
                r"scenario steps\[0\].sleep must be finite",
            ),
            (
                {
                    "steps": [{"sleep": True}, {"fuzz": "[FUZZ]"}],
                },
                r"scenario steps\[0\].sleep must be a number",
            ),
            (
                {
                    "steps": [
                        {
                            "fuzz": {
                                "template": "[FUZZ]",
                                "fallback": "fallback:[FUZZ]",
                            }
                        }
                    ],
                },
                r"scenario steps\[0\].fuzz fallback cannot contain \[FUZZ\]",
            ),
            (
                {
                    "steps": [
                        {"fuzz": "[FUZZ]"},
                        {"expect": {"contains": "ok", "regex": "ok"}},
                    ],
                },
                r"scenario steps\[1\].expect must define exactly one assertion",
            ),
            (
                {
                    "steps": [
                        {"fuzz": "[FUZZ]"},
                        {"expect": {"status": 200}},
                    ],
                },
                r"unsupported scenario steps\[1\].expect key: status",
            ),
            (
                {
                    "steps": [
                        {"fuzz": "[FUZZ]"},
                        {"capture": {"json": {"id": "id"}, "regex": {"var": "x"}}},
                    ],
                },
                r"scenario steps\[1\].capture must define exactly one extractor",
            ),
            (
                {
                    "steps": [
                        {"fuzz": "[FUZZ]"},
                        {
                            "capture": {
                                "json": {"var": "id", "path": "id", "extra": "x"}
                            }
                        },
                    ],
                },
                r"scenario steps\[1\].capture.json var/path form cannot include extra keys",
            ),
            (
                {
                    "steps": [
                        {"fuzz": "[FUZZ]"},
                        {"capture": {"regex": {"var": "id"}}},
                    ],
                },
                r"scenario steps\[1\].capture.regex missing pattern",
            ),
            (
                {
                    "steps": [
                        {"fuzz": "[FUZZ]"},
                        {
                            "capture": {
                                "regex": {
                                    "var": "id",
                                    "pattern": "id=(.+)",
                                    "grop": 1,
                                }
                            }
                        },
                    ],
                },
                r"unsupported scenario steps\[1\].capture.regex key: grop",
            ),
            (
                {
                    "steps": [
                        {"fuzz": "[FUZZ]"},
                        {
                            "capture": {
                                "regex": {
                                    "var": "id",
                                    "pattern": "id=(.+)",
                                    "group": "x",
                                }
                            }
                        },
                    ],
                },
                r"scenario steps\[1\].capture.regex.group must be an integer",
            ),
            (
                {
                    "steps": [
                        {"fuzz": "[FUZZ]"},
                        {
                            "capture": {
                                "regex": {
                                    "var": "id",
                                    "pattern": "id=(.+)",
                                    "group": 1.5,
                                }
                            }
                        },
                    ],
                },
                r"scenario steps\[1\].capture.regex.group must be an integer",
            ),
            (
                {
                    "steps": [
                        {"fuzz": "[FUZZ]"},
                        {
                            "capture": {
                                "regex": {
                                    "var": "id",
                                    "pattern": "id=(.+)",
                                    "group": -1,
                                }
                            }
                        },
                    ],
                },
                r"scenario steps\[1\].capture.regex.group must be non-negative",
            ),
        ],
    )
    def test_load_scenario_rejects_malformed_nested_sections(
        self, tmp_path, payload, message
    ):
        scenario_path = _write_scenario(tmp_path / "scenario.json", payload)

        with pytest.raises(ScenarioError, match=message):
            load_scenario(scenario_path)

    def test_stateful_scenario_with_pre_http(
        self, echo_server, auth_http_server, tmp_path
    ):
        scenario_path = _write_scenario(
            tmp_path / "scenario.json",
            {
                "pre_http": {
                    "method": "POST",
                    "url": auth_http_server,
                    "body": {"user": "test", "pass": "test"},
                    "capture": {"json": {"token": "token"}},
                },
                "connect": {
                    "path": "/stateful",
                    "headers": {"Authorization": "Bearer ${token}"},
                },
                "setup": [
                    {"send": {"op": "login", "user": "test", "pass": "test"}},
                    {"expect": {"json": {"ok": True}}},
                    {"capture": {"json": {"ws_token": "token"}}},
                    {"send": {"op": "subscribe", "topic": "orders"}},
                    {"expect": {"contains": "subscribed"}},
                    {"capture": {"json": {"session_id": "session"}}},
                ],
                "steps": [
                    {
                        "fuzz": {
                            "name": "update-id",
                            "template": {
                                "op": "update",
                                "session": "${session_id}",
                                "id": "[FUZZ]",
                            },
                        }
                    },
                    {"expect": {"json": {"ok": True, "session": "${session_id}"}}},
                    {"capture": {"json": {"echoed": "echo"}}},
                ],
            },
        )
        scenario = load_scenario(scenario_path)
        result = asyncio.run(
            run_scenario_iteration(
                scenario,
                echo_server,
                b"abc-123",
                "text",
                2.0,
                None,
                select_fuzz_step(scenario, 0, "round-robin"),
            )
        )

        assert result.error is None
        assert result.response is not None
        payload = json.loads(result.response.decode())
        assert payload["echo"] == "abc-123"
        assert payload["session"] == "session-42"

    def test_pre_http_honors_insecure_tls_override(self, tmp_path, monkeypatch):
        scenario = load_scenario(
            _write_scenario(
                tmp_path / "scenario.json",
                {
                    "pre_http": {
                        "url": "https://auth.example.test/login",
                        "capture": {"json": {"token": "token"}},
                    },
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
            )
        )
        seen: dict[str, object] = {}

        def fake_http_request(
            method: str,
            url: str,
            headers: dict[str, str],
            data: bytes | None,
            timeout: float,
            ssl_context: ssl.SSLContext | None = None,
        ) -> tuple[int, object, bytes]:
            seen["url"] = url
            seen["ssl_context"] = ssl_context
            return (200, {}, b'{"token":"abc"}')

        monkeypatch.setattr("wsfuzz.scenario._http_request", fake_http_request)

        variables = asyncio.run(
            _run_pre_http(
                scenario,
                2.0,
                ConnectOpts(insecure=True),
            )
        )

        assert variables == {"token": "abc"}
        assert seen["url"] == "https://auth.example.test/login"
        assert isinstance(seen["ssl_context"], ssl.SSLContext)
        assert seen["ssl_context"].verify_mode == ssl.CERT_NONE
        assert seen["ssl_context"].check_hostname is False

    def test_pre_http_missing_ca_is_transport_config_error(self, tmp_path):
        scenario = load_scenario(
            _write_scenario(
                tmp_path / "scenario.json",
                {
                    "pre_http": {"url": "https://auth.example.test/login"},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
            )
        )

        result = asyncio.run(
            run_scenario_iteration(
                scenario,
                "ws://example.test/socket",
                b"payload",
                "text",
                1.0,
                ConnectOpts(ca_file="/nonexistent/ca.pem"),
                select_fuzz_step(scenario, 0, "round-robin"),
            )
        )

        assert result.error_type == "transport_config"

    def test_pre_http_honors_expected_error_status(self, tmp_path, monkeypatch):
        scenario = load_scenario(
            _write_scenario(
                tmp_path / "scenario.json",
                {
                    "pre_http": {
                        "url": "https://auth.example.test/login",
                        "expect_status": 401,
                        "capture": {
                            "json": {"reason": "error"},
                            "headers": {"request_id": "X-Request-Id"},
                        },
                    },
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
            )
        )

        def fake_urlopen(request, **kwargs):
            headers = Message()
            headers["X-Request-Id"] = "req-1"
            raise HTTPError(
                request.full_url,
                401,
                "Unauthorized",
                headers,
                BytesIO(b'{"error":"bad-token"}'),
            )

        monkeypatch.setattr("wsfuzz.scenario.urlopen", fake_urlopen)

        variables = asyncio.run(_run_pre_http(scenario, 2.0))

        assert variables == {
            "reason": "bad-token",
            "request_id": "req-1",
        }

    def test_pre_http_missing_captured_header_is_scenario_error(
        self, tmp_path, monkeypatch
    ):
        scenario = load_scenario(
            _write_scenario(
                tmp_path / "scenario.json",
                {
                    "pre_http": {
                        "url": "https://auth.example.test/login",
                        "capture": {"headers": {"request_id": "X-Request-Id"}},
                    },
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
            )
        )

        def fake_http_request(
            method: str,
            url: str,
            headers: dict[str, str],
            data: bytes | None,
            timeout: float,
            ssl_context: ssl.SSLContext | None = None,
        ) -> tuple[int, Message, bytes]:
            return (200, Message(), b"")

        monkeypatch.setattr("wsfuzz.scenario._http_request", fake_http_request)

        with pytest.raises(
            ScenarioError,
            match="pre_http response missing header 'X-Request-Id'",
        ):
            asyncio.run(_run_pre_http(scenario, 2.0))

    def test_rendered_connect_path_rejects_full_url(self, tmp_path, monkeypatch):
        scenario = load_scenario(
            _write_scenario(
                tmp_path / "scenario.json",
                {
                    "pre_http": {
                        "url": "http://auth.example.test",
                        "capture": {"json": {"socket_path": "socket_path"}},
                    },
                    "connect": {"path": "${socket_path}"},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
            )
        )

        def fake_http_request(
            method: str,
            url: str,
            headers: dict[str, str],
            data: bytes | None,
            timeout: float,
            ssl_context: ssl.SSLContext | None = None,
        ) -> tuple[int, object, bytes]:
            return (200, {}, b'{"socket_path":"ws://other.example.test/socket"}')

        monkeypatch.setattr("wsfuzz.scenario._http_request", fake_http_request)

        result = asyncio.run(
            run_scenario_iteration(
                scenario,
                "ws://example.test/base",
                b"payload",
                "text",
                2.0,
                None,
                select_fuzz_step(scenario, 0, "round-robin"),
            )
        )

        assert result.error_type == "ScenarioError"
        assert result.error == "scenario connect.path must be a path, not a URL"

    def test_rendered_connect_url_rejects_non_websocket_url(
        self, tmp_path, monkeypatch
    ):
        scenario = load_scenario(
            _write_scenario(
                tmp_path / "scenario.json",
                {
                    "pre_http": {
                        "url": "http://auth.example.test",
                        "capture": {"json": {"socket_url": "socket_url"}},
                    },
                    "connect": {"url": "${socket_url}"},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
            )
        )

        def fake_http_request(
            method: str,
            url: str,
            headers: dict[str, str],
            data: bytes | None,
            timeout: float,
            ssl_context: ssl.SSLContext | None = None,
        ) -> tuple[int, object, bytes]:
            return (200, {}, b'{"socket_url":"http://example.test/socket"}')

        monkeypatch.setattr("wsfuzz.scenario._http_request", fake_http_request)

        result = asyncio.run(
            run_scenario_iteration(
                scenario,
                "ws://example.test/base",
                b"payload",
                "text",
                2.0,
                None,
                select_fuzz_step(scenario, 0, "round-robin"),
            )
        )

        assert result.error_type == "ScenarioError"
        assert result.error == "scenario connect.url must be a ws:// or wss:// URL"

    def test_rendered_connect_header_rejects_newlines(self, tmp_path, monkeypatch):
        scenario = load_scenario(
            _write_scenario(
                tmp_path / "scenario.json",
                {
                    "pre_http": {
                        "url": "http://auth.example.test",
                        "capture": {"json": {"token": "token"}},
                    },
                    "connect": {"headers": {"Authorization": "${token}"}},
                    "steps": [{"fuzz": "[FUZZ]"}],
                },
            )
        )

        def fake_http_request(
            method: str,
            url: str,
            headers: dict[str, str],
            data: bytes | None,
            timeout: float,
            ssl_context: ssl.SSLContext | None = None,
        ) -> tuple[int, object, bytes]:
            return (200, {}, b'{"token":"ok\\r\\nX-Evil: 1"}')

        monkeypatch.setattr("wsfuzz.scenario._http_request", fake_http_request)

        result = asyncio.run(
            run_scenario_iteration(
                scenario,
                "ws://example.test/base",
                b"payload",
                "text",
                2.0,
                None,
                select_fuzz_step(scenario, 0, "round-robin"),
            )
        )

        assert result.error_type == "ScenarioError"
        assert result.error == "headers must not contain newlines"

    def test_round_robin_rotates_across_multiple_fuzz_steps(self, tmp_path):
        scenario = load_scenario(
            _write_scenario(
                tmp_path / "scenario.json",
                {
                    "steps": [
                        {"fuzz": {"name": "first", "template": {"id": "[FUZZ]"}}},
                        {"fuzz": {"name": "second", "template": {"id": "[FUZZ]"}}},
                    ]
                },
            )
        )

        assert select_fuzz_step(scenario, 0, "round-robin").name == "first"
        assert select_fuzz_step(scenario, 1, "round-robin").name == "second"
        assert select_fuzz_step(scenario, 2, "round-robin").name == "first"

    def test_round_robin_skips_follow_up_expect_for_inactive_fuzz(
        self, echo_server, tmp_path
    ):
        scenario = load_scenario(
            _write_scenario(
                tmp_path / "scenario.json",
                {
                    "steps": [
                        {"fuzz": {"name": "first", "template": "first:[FUZZ]"}},
                        {"expect": {"contains": "first:"}},
                        {
                            "capture": {
                                "regex": {"var": "first_echo", "pattern": "first:(.+)"}
                            }
                        },
                        {"fuzz": {"name": "second", "template": "second:[FUZZ]"}},
                        {"expect": {"contains": "second:"}},
                    ]
                },
            )
        )

        result = asyncio.run(
            run_scenario_iteration(
                scenario,
                echo_server,
                b"value",
                "text",
                2.0,
                None,
                select_fuzz_step(scenario, 1, "round-robin"),
            )
        )

        assert result.error is None
        assert result.response == b"second:value"

    def test_binary_scenario_preserves_raw_fuzz_bytes(self, echo_server, tmp_path):
        scenario = load_scenario(
            _write_scenario(
                tmp_path / "scenario.json",
                {
                    "steps": [
                        {"fuzz": {"name": "bytes", "template": "[FUZZ]"}},
                        {"expect": {"contains": ""}},
                    ]
                },
            )
        )

        payload = b"\xff\x00\x80A"
        result = asyncio.run(
            run_scenario_iteration(
                scenario,
                echo_server,
                payload,
                "binary",
                2.0,
                None,
                select_fuzz_step(scenario, 0, "round-robin"),
            )
        )

        assert result.error is None
        assert result.response == payload

    def test_structured_fuzz_payload_can_use_template_field(
        self, echo_server, tmp_path
    ):
        scenario = load_scenario(
            _write_scenario(
                tmp_path / "scenario.json",
                {
                    "steps": [
                        {"fuzz": {"op": "render", "template": "[FUZZ]"}},
                        {"expect": {"json": {"op": "render", "template": "card"}}},
                    ]
                },
            )
        )

        result = asyncio.run(
            run_scenario_iteration(
                scenario,
                echo_server,
                b"card",
                "text",
                2.0,
                None,
                select_fuzz_step(scenario, 0, "round-robin"),
            )
        )

        assert result.error is None

    def test_structured_fuzz_payload_can_be_single_template_field(
        self, echo_server, tmp_path
    ):
        scenario = load_scenario(
            _write_scenario(
                tmp_path / "scenario.json",
                {
                    "steps": [
                        {"fuzz": {"template": "[FUZZ]"}},
                        {"expect": {"json": {"template": "card"}}},
                    ]
                },
            )
        )

        result = asyncio.run(
            run_scenario_iteration(
                scenario,
                echo_server,
                b"card",
                "text",
                2.0,
                None,
                select_fuzz_step(scenario, 0, "round-robin"),
            )
        )

        assert result.error is None

    def test_structured_fuzz_payload_can_use_non_string_name_field(
        self, echo_server, tmp_path
    ):
        scenario = load_scenario(
            _write_scenario(
                tmp_path / "scenario.json",
                {
                    "steps": [
                        {"fuzz": {"id": "[FUZZ]", "name": 123}},
                        {"expect": {"json": {"id": "abc", "name": 123}}},
                    ]
                },
            )
        )

        assert scenario.fuzz_steps[0].name is None
        result = asyncio.run(
            run_scenario_iteration(
                scenario,
                echo_server,
                b"abc",
                "text",
                2.0,
                None,
                select_fuzz_step(scenario, 0, "round-robin"),
            )
        )

        assert result.error is None

    def test_capture_regex_missing_group_is_scenario_error(self, echo_server, tmp_path):
        scenario = load_scenario(
            _write_scenario(
                tmp_path / "scenario.json",
                {
                    "steps": [
                        {"fuzz": "id=[FUZZ]"},
                        {"expect": {"contains": "id="}},
                        {
                            "capture": {
                                "regex": {
                                    "var": "id",
                                    "pattern": r"id=(.+)",
                                    "group": 2,
                                }
                            }
                        },
                    ]
                },
            )
        )

        result = asyncio.run(
            run_scenario_iteration(
                scenario,
                echo_server,
                b"123",
                "text",
                2.0,
                None,
                select_fuzz_step(scenario, 0, "round-robin"),
            )
        )

        assert result.error_type == "ScenarioError"
        assert result.error == "capture regex group 2 is not available"

    def test_invalid_runtime_regex_is_scenario_error(self, echo_server, tmp_path):
        scenario = load_scenario(
            _write_scenario(
                tmp_path / "scenario.json",
                {
                    "steps": [
                        {"fuzz": "[FUZZ]"},
                        {"expect": {"regex": "["}},
                    ]
                },
            )
        )

        result = asyncio.run(
            run_scenario_iteration(
                scenario,
                echo_server,
                b"payload",
                "text",
                2.0,
                None,
                select_fuzz_step(scenario, 0, "round-robin"),
            )
        )

        assert result.error_type == "ScenarioError"
        assert result.error is not None
        assert result.error.startswith("scenario expect regex is invalid:")

    def test_missing_json_capture_path_is_scenario_error(self, echo_server, tmp_path):
        scenario = load_scenario(
            _write_scenario(
                tmp_path / "scenario.json",
                {
                    "steps": [
                        {"fuzz": '{"ok":true,"value":"[FUZZ]"}'},
                        {"expect": {"json": {"ok": True}}},
                        {"capture": {"json": {"missing": "missing"}}},
                    ]
                },
            )
        )

        result = asyncio.run(
            run_scenario_iteration(
                scenario,
                echo_server,
                b"ignored",
                "text",
                2.0,
                None,
                select_fuzz_step(scenario, 0, "round-robin"),
            )
        )

        assert result.error_type == "ScenarioError"
        assert result.error == "JSON path 'missing' missing key 'missing'"

    def test_invalid_json_expectation_response_is_scenario_error(
        self, echo_server, tmp_path
    ):
        scenario = load_scenario(
            _write_scenario(
                tmp_path / "scenario.json",
                {
                    "steps": [
                        {"fuzz": "[FUZZ]"},
                        {"expect": {"json": {"ok": True}}},
                    ]
                },
            )
        )

        result = asyncio.run(
            run_scenario_iteration(
                scenario,
                echo_server,
                b"not-json",
                "text",
                2.0,
                None,
                select_fuzz_step(scenario, 0, "round-robin"),
            )
        )

        assert result.error_type == "ScenarioError"
        assert result.error == "scenario expect JSON response is not valid JSON"

    def test_missing_template_variable_is_scenario_error(self, echo_server, tmp_path):
        scenario = load_scenario(
            _write_scenario(
                tmp_path / "scenario.json",
                {
                    "steps": [{"fuzz": "${missing}:[FUZZ]"}],
                },
            )
        )

        result = asyncio.run(
            run_scenario_iteration(
                scenario,
                echo_server,
                b"payload",
                "text",
                2.0,
                None,
                select_fuzz_step(scenario, 0, "round-robin"),
            )
        )

        assert result.error_type == "ScenarioError"
        assert result.error == "scenario variable 'missing' is not defined"

    def test_skipped_round_robin_branch_does_not_sleep(self, echo_server, tmp_path):
        scenario = load_scenario(
            _write_scenario(
                tmp_path / "scenario.json",
                {
                    "steps": [
                        {"fuzz": {"name": "first", "template": "first:[FUZZ]"}},
                        {"sleep": 0.3},
                        {"expect": {"contains": "first:"}},
                        {"fuzz": {"name": "second", "template": "second:[FUZZ]"}},
                        {"expect": {"contains": "second:"}},
                    ]
                },
            )
        )

        start = time.monotonic()
        result = asyncio.run(
            run_scenario_iteration(
                scenario,
                echo_server,
                b"value",
                "text",
                2.0,
                None,
                select_fuzz_step(scenario, 1, "round-robin"),
            )
        )
        elapsed = time.monotonic() - start

        assert result.error is None
        assert result.response == b"second:value"
        assert elapsed < 0.2, f"skipped branch slept for {elapsed:.3f}s"

    def test_reuse_connection_keeps_single_session(self, echo_server, tmp_path):
        scenario = load_scenario(
            _write_scenario(
                tmp_path / "reuse.json",
                {
                    "connect": {"path": "/reuse"},
                    "setup": [
                        {"send": {"op": "hello"}},
                        {"expect": {"json": {"connection_id": "conn-1"}}},
                        {"capture": {"json": {"connection_id": "connection_id"}}},
                    ],
                    "steps": [
                        {
                            "fuzz": {
                                "name": "ping",
                                "template": {"op": "ping", "value": "[FUZZ]"},
                            }
                        },
                        {
                            "expect": {
                                "json": {
                                    "connection_id": "${connection_id}",
                                }
                            }
                        },
                    ],
                },
            )
        )

        async def run_session() -> None:
            session = ScenarioSession(scenario, echo_server, "text", 2.0, None)
            try:
                first = await session.run(
                    b"one",
                    select_fuzz_step(scenario, 0, "round-robin"),
                )
                second = await session.run(
                    b"two",
                    select_fuzz_step(scenario, 1, "round-robin"),
                )
            finally:
                await session.close()
            assert first.error is None
            assert second.error is None

        asyncio.run(run_session())

        assert reuse_connection_count() == 1


class TestScenarioIntegration:
    def test_fuzzer_logs_scenario_crash_metadata(
        self, echo_server, tmp_path, monkeypatch
    ):
        scenario_path = _write_scenario(
            tmp_path / "scenario.json",
            {
                "connect": {"path": "/error"},
                "steps": [
                    {
                        "fuzz": {
                            "name": "boom",
                            "template": "[FUZZ]",
                        }
                    },
                    {"expect": {"contains": "never-happens"}},
                ],
            },
        )

        async def fake_mutate_async(seed_data, radamsa_path="radamsa", seed_num=None):
            return b"boom"

        monkeypatch.setattr("wsfuzz.fuzzer.mutate_async", fake_mutate_async)

        run(
            FuzzConfig(
                target=echo_server,
                mode="text",
                scenario=scenario_path,
                iterations=1,
                timeout=2.0,
                log_dir=tmp_path / "crashes",
            )
        )

        crash_txt = next((tmp_path / "crashes").glob("crash_*.txt")).read_text()
        crash_snapshot = next((tmp_path / "crashes").glob("crash_*.scenario.json"))
        assert f"scenario_path: {scenario_path}" in crash_txt
        assert "scenario_fuzz_name: boom" in crash_txt
        assert "scenario_fuzz_ordinal: 0" in crash_txt
        assert json.loads(crash_snapshot.read_text()) == json.loads(
            scenario_path.read_text()
        )

    def test_replay_uses_scenario_metadata(self, tmp_path, monkeypatch):
        scenario_path = _write_scenario(
            tmp_path / "scenario.json",
            {"steps": [{"fuzz": {"name": "boom", "template": "[FUZZ]"}}]},
        )
        crash_file = tmp_path / "crash_0_1.bin"
        crash_file.write_bytes(b"payload")
        crash_file.with_suffix(".txt").write_text(
            f"scenario_path: {scenario_path}\nscenario_fuzz_ordinal: 0\n"
        )
        seen: dict[str, object] = {}

        async def fake_run_scenario_iteration(
            scenario,
            uri,
            payload,
            mode,
            timeout,
            opts,
            fuzz_step,
        ):
            seen["path"] = scenario.path
            seen["uri"] = uri
            seen["payload"] = payload
            seen["mode"] = mode
            seen["ordinal"] = fuzz_step.ordinal
            seen["opts"] = opts
            from wsfuzz.transport import TransportResult

            return TransportResult(duration_ms=1.0)

        monkeypatch.setattr(
            "wsfuzz.fuzzer.run_scenario_iteration",
            fake_run_scenario_iteration,
        )

        run(
            FuzzConfig(
                target="ws://example.test/socket",
                mode="text",
                timeout=1.0,
                log_dir=tmp_path / "unused",
                replay=[crash_file],
            )
        )

        assert seen == {
            "path": scenario_path,
            "uri": "ws://example.test/socket",
            "payload": b"payload",
            "mode": "text",
            "ordinal": 0,
            "opts": None,
        }

    def test_replay_prefers_recorded_metadata_over_cli_scenario(
        self, tmp_path, monkeypatch
    ):
        metadata_scenario = _write_scenario(
            tmp_path / "metadata.json",
            {"steps": [{"fuzz": {"name": "metadata", "template": "[FUZZ]"}}]},
        )
        cli_scenario = _write_scenario(
            tmp_path / "cli.json",
            {"steps": [{"fuzz": {"name": "cli", "template": "[FUZZ]"}}]},
        )
        crash_file = tmp_path / "crash_0_1.bin"
        crash_file.write_bytes(b"payload")
        crash_file.with_suffix(".txt").write_text(
            f"scenario_path: {metadata_scenario}\nscenario_fuzz_ordinal: 0\n"
        )
        seen: dict[str, object] = {}

        async def fake_run_scenario_iteration(
            scenario,
            uri,
            payload,
            mode,
            timeout,
            opts,
            fuzz_step,
        ):
            seen["path"] = scenario.path
            seen["name"] = fuzz_step.name
            from wsfuzz.transport import TransportResult

            return TransportResult(duration_ms=1.0)

        monkeypatch.setattr(
            "wsfuzz.fuzzer.run_scenario_iteration",
            fake_run_scenario_iteration,
        )

        run(
            FuzzConfig(
                target="ws://example.test/socket",
                mode="text",
                timeout=1.0,
                log_dir=tmp_path / "unused",
                replay=[crash_file],
                scenario=cli_scenario,
            )
        )

        assert seen == {
            "path": metadata_scenario.resolve(),
            "name": "metadata",
        }

    def test_replay_resolves_relative_scenario_path_from_crash_file(
        self, tmp_path, monkeypatch
    ):
        scenarios_dir = tmp_path / "scenarios"
        scenarios_dir.mkdir()
        scenario_path = _write_scenario(
            scenarios_dir / "scenario.json",
            {"steps": [{"fuzz": {"name": "boom", "template": "[FUZZ]"}}]},
        )
        crash_file = tmp_path / "crash_0_1.bin"
        crash_file.write_bytes(b"payload")
        crash_file.with_suffix(".txt").write_text(
            "scenario_path: scenarios/scenario.json\nscenario_fuzz_ordinal: 0\n"
        )
        seen: dict[str, object] = {}

        async def fake_run_scenario_iteration(
            scenario,
            uri,
            payload,
            mode,
            timeout,
            opts,
            fuzz_step,
        ):
            seen["path"] = scenario.path
            seen["uri"] = uri
            seen["payload"] = payload
            seen["mode"] = mode
            seen["ordinal"] = fuzz_step.ordinal
            seen["opts"] = opts
            from wsfuzz.transport import TransportResult

            return TransportResult(duration_ms=1.0)

        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)
        monkeypatch.setattr(
            "wsfuzz.fuzzer.run_scenario_iteration",
            fake_run_scenario_iteration,
        )

        run(
            FuzzConfig(
                target="ws://example.test/socket",
                mode="text",
                timeout=1.0,
                log_dir=tmp_path / "unused",
                replay=[crash_file],
            )
        )

        assert seen == {
            "path": scenario_path.resolve(),
            "uri": "ws://example.test/socket",
            "payload": b"payload",
            "mode": "text",
            "ordinal": 0,
            "opts": None,
        }

    def test_replay_prefers_saved_scenario_snapshot(self, tmp_path, monkeypatch):
        scenario_path = _write_scenario(
            tmp_path / "scenario.json",
            {"steps": [{"fuzz": {"name": "disk", "template": "[FUZZ]"}}]},
        )
        crash_file = tmp_path / "crash_0_1.bin"
        crash_file.write_bytes(b"payload")
        crash_file.with_suffix(".txt").write_text(
            f"scenario_path: {scenario_path}\nscenario_fuzz_ordinal: 0\n"
        )
        crash_file.with_suffix(".scenario.json").write_text(
            json.dumps(
                {"steps": [{"fuzz": {"name": "snapshot", "template": "[FUZZ]"}}]}
            )
        )
        scenario_path.write_text(
            json.dumps({"steps": [{"fuzz": {"name": "mutated", "template": "[FUZZ]"}}]})
        )
        seen: dict[str, object] = {}

        async def fake_run_scenario_iteration(
            scenario,
            uri,
            payload,
            mode,
            timeout,
            opts,
            fuzz_step,
        ):
            seen["path"] = scenario.path
            seen["name"] = fuzz_step.name
            from wsfuzz.transport import TransportResult

            return TransportResult(duration_ms=1.0)

        monkeypatch.setattr(
            "wsfuzz.fuzzer.run_scenario_iteration",
            fake_run_scenario_iteration,
        )

        run(
            FuzzConfig(
                target="ws://example.test/socket",
                mode="text",
                timeout=1.0,
                log_dir=tmp_path / "unused",
                replay=[crash_file],
            )
        )

        assert seen == {
            "path": crash_file.with_suffix(".scenario.json").resolve(),
            "name": "snapshot",
        }

    def test_replay_restores_saved_scenario_mode(self, tmp_path, monkeypatch):
        crash_file = tmp_path / "crash_0_1.bin"
        crash_file.write_bytes(b"payload")
        crash_file.with_suffix(".txt").write_text(
            "scenario_fuzz_ordinal: 0\nscenario_mode: text\n"
        )
        crash_file.with_suffix(".scenario.json").write_text(
            json.dumps(
                {"steps": [{"fuzz": {"name": "snapshot", "template": "[FUZZ]"}}]}
            )
        )
        seen: dict[str, object] = {}

        async def fake_run_scenario_iteration(
            scenario,
            uri,
            payload,
            mode,
            timeout,
            opts,
            fuzz_step,
        ):
            seen["mode"] = mode
            seen["name"] = fuzz_step.name
            from wsfuzz.transport import TransportResult

            return TransportResult(duration_ms=1.0)

        monkeypatch.setattr(
            "wsfuzz.fuzzer.run_scenario_iteration",
            fake_run_scenario_iteration,
        )

        run(
            FuzzConfig(
                target="ws://example.test/socket",
                timeout=1.0,
                log_dir=tmp_path / "unused",
                replay=[crash_file],
            )
        )

        assert seen == {
            "mode": "text",
            "name": "snapshot",
        }

    def test_replay_rejects_invalid_scenario_fuzz_ordinal(self, tmp_path):
        crash_file = tmp_path / "crash_0_1.bin"
        crash_file.write_bytes(b"payload")
        crash_file.with_suffix(".txt").write_text("scenario_fuzz_ordinal: nope\n")
        crash_file.with_suffix(".scenario.json").write_text(
            json.dumps({"steps": [{"fuzz": "[FUZZ]"}]})
        )

        with pytest.raises(
            ValueError,
            match="scenario_fuzz_ordinal must be an integer",
        ):
            run(
                FuzzConfig(
                    target="ws://example.test/socket",
                    timeout=1.0,
                    log_dir=tmp_path / "unused",
                    replay=[crash_file],
                )
            )

    def test_replay_rejects_out_of_range_scenario_fuzz_ordinal(self, tmp_path):
        crash_file = tmp_path / "crash_0_1.bin"
        crash_file.write_bytes(b"payload")
        crash_file.with_suffix(".txt").write_text("scenario_fuzz_ordinal: 1\n")
        crash_file.with_suffix(".scenario.json").write_text(
            json.dumps({"steps": [{"fuzz": "[FUZZ]"}]})
        )

        with pytest.raises(
            ValueError,
            match="scenario_fuzz_ordinal 1 is out of range",
        ):
            run(
                FuzzConfig(
                    target="ws://example.test/socket",
                    timeout=1.0,
                    log_dir=tmp_path / "unused",
                    replay=[crash_file],
                )
            )

    def test_replay_rejects_invalid_session_history_payload(self, tmp_path):
        crash_file = tmp_path / "crash_0_1.bin"
        crash_file.write_bytes(b"payload")
        crash_file.with_suffix(".txt").write_text("scenario_fuzz_ordinal: 0\n")
        crash_file.with_suffix(".scenario.json").write_text(
            json.dumps({"steps": [{"fuzz": "[FUZZ]"}]})
        )
        crash_file.with_suffix(".scenario-session.json").write_text(
            json.dumps(
                {
                    "entries": [
                        {
                            "fuzz_ordinal": 0,
                            "payload_b64": "not@base64",
                        }
                    ]
                }
            )
        )

        with pytest.raises(
            ValueError,
            match="scenario session history entry 0 payload_b64 is invalid",
        ):
            run(
                FuzzConfig(
                    target="ws://example.test/socket",
                    timeout=1.0,
                    log_dir=tmp_path / "unused",
                    replay=[crash_file],
                )
            )

    @pytest.mark.parametrize(
        ("entry", "message"),
        [
            ([], "scenario session history entry 0 must be an object"),
            (
                {"payload_b64": "cHJpb3I="},
                "scenario session history entry 0 missing fuzz_ordinal",
            ),
            (
                {"fuzz_ordinal": 0, "payload_b64": 123},
                "scenario session history entry 0 payload_b64 must be a string",
            ),
        ],
    )
    def test_replay_rejects_malformed_session_history_entry(
        self, tmp_path, entry, message
    ):
        crash_file = tmp_path / "crash_0_1.bin"
        crash_file.write_bytes(b"payload")
        crash_file.with_suffix(".txt").write_text("scenario_fuzz_ordinal: 0\n")
        crash_file.with_suffix(".scenario.json").write_text(
            json.dumps({"steps": [{"fuzz": "[FUZZ]"}]})
        )
        crash_file.with_suffix(".scenario-session.json").write_text(
            json.dumps({"entries": [entry]})
        )

        with pytest.raises(ValueError, match=message):
            run(
                FuzzConfig(
                    target="ws://example.test/socket",
                    timeout=1.0,
                    log_dir=tmp_path / "unused",
                    replay=[crash_file],
                )
            )

    def test_replay_rejects_non_text_session_history(self, tmp_path):
        crash_file = tmp_path / "crash_0_1.bin"
        crash_file.write_bytes(b"payload")
        crash_file.with_suffix(".txt").write_text("scenario_fuzz_ordinal: 0\n")
        crash_file.with_suffix(".scenario.json").write_text(
            json.dumps({"steps": [{"fuzz": "[FUZZ]"}]})
        )
        crash_file.with_suffix(".scenario-session.json").write_bytes(b"\xff\xfe\xfd")

        with pytest.raises(
            ValueError,
            match="scenario session history cannot be read",
        ):
            run(
                FuzzConfig(
                    target="ws://example.test/socket",
                    timeout=1.0,
                    log_dir=tmp_path / "unused",
                    replay=[crash_file],
                )
            )

    def test_replay_rehydrates_reused_session_history(self, tmp_path, monkeypatch):
        crash_file = tmp_path / "crash_0_1.bin"
        crash_file.write_bytes(b"current")
        crash_file.with_suffix(".txt").write_text(
            "scenario_fuzz_ordinal: 0\nscenario_mode: text\n"
        )
        crash_file.with_suffix(".scenario.json").write_text(
            json.dumps(
                {"steps": [{"fuzz": {"name": "snapshot", "template": "[FUZZ]"}}]}
            )
        )
        crash_file.with_suffix(".scenario-session.json").write_text(
            json.dumps(
                {
                    "entries": [
                        {
                            "fuzz_ordinal": 0,
                            "payload_b64": "cHJpb3I=",
                        }
                    ]
                }
            )
        )
        seen: list[tuple[bytes, int]] = []

        class FakeSession:
            def __init__(self, scenario, uri, mode, timeout, opts) -> None:
                self.mode = mode

            async def run(self, payload: bytes, fuzz_step) -> object:
                seen.append((payload, fuzz_step.ordinal))
                from wsfuzz.transport import TransportResult

                return TransportResult(response=b"ok", duration_ms=1.0)

            async def close(self) -> None:
                return None

        monkeypatch.setattr("wsfuzz.fuzzer.ScenarioSession", FakeSession)

        run(
            FuzzConfig(
                target="ws://example.test/socket",
                timeout=1.0,
                log_dir=tmp_path / "unused",
                replay=[crash_file],
            )
        )

        assert seen == [
            (b"prior", 0),
            (b"current", 0),
        ]

    def test_reused_session_crash_transcript_is_capped(self, tmp_path, monkeypatch):
        scenario_path = _write_scenario(
            tmp_path / "scenario.json",
            {"steps": [{"fuzz": {"name": "snapshot", "template": "[FUZZ]"}}]},
        )
        payloads = iter([b"one", b"two", b"three"])

        async def fake_mutate_async(seed_data, radamsa_path="radamsa", seed_num=None):
            return next(payloads)

        class FakeSession:
            def __init__(self, scenario, uri, mode, timeout, opts) -> None:
                self.calls = 0

            async def run(self, payload: bytes, fuzz_step) -> object:
                self.calls += 1
                from wsfuzz.transport import TransportResult

                if self.calls < 3:
                    return TransportResult(response=b"ok", duration_ms=1.0)
                return TransportResult(
                    error="boom",
                    error_type="boom",
                    duration_ms=1.0,
                )

            async def close(self) -> None:
                return None

        monkeypatch.setattr("wsfuzz.fuzzer.mutate_async", fake_mutate_async)
        monkeypatch.setattr("wsfuzz.fuzzer.ScenarioSession", FakeSession)

        run(
            FuzzConfig(
                target="ws://example.test/socket",
                mode="text",
                scenario=scenario_path,
                scenario_reuse_connection=True,
                scenario_session_history_limit=1,
                iterations=3,
                timeout=1.0,
                log_dir=tmp_path / "crashes",
            )
        )

        transcript = json.loads(
            next(
                (tmp_path / "crashes").glob("crash_*.scenario-session.json")
            ).read_text()
        )
        metadata = next((tmp_path / "crashes").glob("crash_*.txt")).read_text()

        assert transcript == {
            "entries": [
                {
                    "fuzz_ordinal": 0,
                    "payload_b64": "dHdv",
                }
            ]
        }
        assert "scenario_session_history_limit: 1" in metadata
        assert "scenario_session_history_saved: 1" in metadata
        assert "scenario_session_history_truncated: true" in metadata
