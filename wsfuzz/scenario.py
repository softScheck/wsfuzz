import asyncio
import json
import math
import re
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast
from urllib.error import HTTPError, URLError
from urllib.parse import SplitResult, urlsplit, urlunsplit
from urllib.request import Request, urlopen

import websockets

from wsfuzz.transport import (
    ConnectOpts,
    TransportConfigError,
    TransportResult,
    classify_error,
    contains_control_chars,
    handle_close,
    is_http_token,
    make_connect_opts,
    open_connection,
)

_VAR_RE = re.compile(r"\$\{([^}]+)\}")
_FUZZ_CONTROL_KEYS = {"name", "template", "fallback"}


class ScenarioError(Exception):
    pass


@dataclass(frozen=True)
class FuzzStep:
    index: int
    ordinal: int
    name: str | None = None


@dataclass(frozen=True)
class Scenario:
    path: Path
    pre_http: dict[str, Any] | None
    connect: dict[str, Any]
    setup: list[dict[str, Any]]
    steps: list[dict[str, Any]]
    teardown: list[dict[str, Any]]
    fuzz_steps: list[FuzzStep]
    raw_text: str


def load_scenario(path: Path) -> Scenario:
    resolved_path = path.resolve()
    try:
        raw_text = resolved_path.read_text()
    except OSError as exc:
        raise ScenarioError(f"scenario file cannot be read: {resolved_path}") from exc
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ScenarioError(
            f"scenario file is not valid JSON: {resolved_path}"
        ) from exc
    if not isinstance(data, dict):
        raise ScenarioError("scenario root must be a JSON object")

    connect = data.get("connect", {})
    if not isinstance(connect, dict):
        raise ScenarioError("scenario connect must be an object")
    _validate_connect(connect)

    setup = _load_steps(data.get("setup"), "setup")
    steps = _load_steps(data.get("steps"), "steps")
    teardown = _load_steps(data.get("teardown"), "teardown")
    fuzz_steps = _collect_fuzz_steps(steps)
    if not fuzz_steps:
        raise ScenarioError("scenario must define at least one fuzz step")

    pre_http = data.get("pre_http")
    if "pre_http" in data and not isinstance(pre_http, dict):
        raise ScenarioError("scenario pre_http must be an object")
    if pre_http is not None:
        _validate_pre_http(pre_http)

    return Scenario(
        path=resolved_path,
        pre_http=pre_http,
        connect=connect,
        setup=setup,
        steps=steps,
        teardown=teardown,
        fuzz_steps=fuzz_steps,
        raw_text=raw_text,
    )


def select_fuzz_step(scenario: Scenario, iteration: int, mode: str) -> FuzzStep:
    if mode == "first" or len(scenario.fuzz_steps) == 1:
        return scenario.fuzz_steps[0]
    if mode != "round-robin":
        raise ScenarioError(f"unsupported scenario fuzz mode: {mode}")
    return scenario.fuzz_steps[iteration % len(scenario.fuzz_steps)]


def scenario_metadata(
    scenario: Scenario,
    fuzz_step: FuzzStep,
) -> dict[str, str]:
    metadata = {
        "scenario_path": str(scenario.path),
        "scenario_fuzz_index": str(fuzz_step.index),
        "scenario_fuzz_ordinal": str(fuzz_step.ordinal),
    }
    if fuzz_step.name:
        metadata["scenario_fuzz_name"] = fuzz_step.name
    return metadata


async def run_scenario_iteration(
    scenario: Scenario,
    uri: str,
    payload: bytes,
    mode: str,
    timeout: float,
    opts: ConnectOpts | None,
    fuzz_step: FuzzStep,
) -> TransportResult:
    start = time.monotonic()
    variables: dict[str, Any] = {}

    def _elapsed() -> float:
        return (time.monotonic() - start) * 1000

    try:
        variables.update(await _run_pre_http(scenario, timeout, opts))
        resolved_uri, resolved_opts = _resolve_connect(
            uri, opts, scenario.connect, variables
        )
        async with await open_connection(
            resolved_uri,
            timeout,
            resolved_opts,
        ) as ws:
            await _execute_steps(
                ws,
                scenario.setup,
                mode,
                timeout,
                variables,
                payload=None,
                active_fuzz_step=None,
            )
            response = await _execute_steps(
                ws,
                scenario.steps,
                mode,
                timeout,
                variables,
                payload=payload,
                active_fuzz_step=fuzz_step,
            )
            if scenario.teardown:
                await _execute_steps(
                    ws,
                    scenario.teardown,
                    mode,
                    timeout,
                    variables,
                    payload=None,
                    active_fuzz_step=None,
                )
            return TransportResult(response=response, duration_ms=_elapsed())
    except websockets.ConnectionClosed as e:
        return handle_close(e, _elapsed())
    except Exception as e:
        return classify_error(e, _elapsed())


class ScenarioSession:
    def __init__(
        self,
        scenario: Scenario,
        uri: str,
        mode: str,
        timeout: float,
        opts: ConnectOpts | None,
    ) -> None:
        self.scenario = scenario
        self.uri = uri
        self.mode = mode
        self.timeout = timeout
        self.opts = opts
        self._ws: websockets.ClientConnection | None = None
        self._variables: dict[str, Any] = {}

    async def run(self, payload: bytes, fuzz_step: FuzzStep) -> TransportResult:
        start = time.monotonic()

        def _elapsed() -> float:
            return (time.monotonic() - start) * 1000

        try:
            if self._ws is None:
                await self._connect()
            assert self._ws is not None
            response = await _execute_steps(
                self._ws,
                self.scenario.steps,
                self.mode,
                self.timeout,
                self._variables,
                payload=payload,
                active_fuzz_step=fuzz_step,
            )
            return TransportResult(response=response, duration_ms=_elapsed())
        except websockets.ConnectionClosed as e:
            await self.close()
            return handle_close(e, _elapsed())
        except Exception as e:
            await self.close()
            return classify_error(e, _elapsed())

    async def close(self) -> None:
        if self._ws is None:
            self._variables.clear()
            return
        ws = self._ws
        self._ws = None
        try:
            if self.scenario.teardown:
                await _execute_steps(
                    ws,
                    self.scenario.teardown,
                    self.mode,
                    self.timeout,
                    self._variables,
                    payload=None,
                    active_fuzz_step=None,
                )
        except Exception:
            pass
        finally:
            self._variables.clear()
            await ws.close()

    async def _connect(self) -> None:
        self._variables.clear()
        self._variables.update(
            await _run_pre_http(self.scenario, self.timeout, self.opts)
        )
        resolved_uri, resolved_opts = _resolve_connect(
            self.uri,
            self.opts,
            self.scenario.connect,
            self._variables,
        )
        self._ws = await open_connection(
            resolved_uri,
            self.timeout,
            resolved_opts,
        )
        if self.scenario.setup:
            await _execute_steps(
                self._ws,
                self.scenario.setup,
                self.mode,
                self.timeout,
                self._variables,
                payload=None,
                active_fuzz_step=None,
            )


def _load_steps(raw_steps: Any, section: str) -> list[dict[str, Any]]:
    if raw_steps is None:
        return []
    if not isinstance(raw_steps, list):
        raise ScenarioError(f"scenario {section} must be a list")
    steps: list[dict[str, Any]] = []
    valid_keys = {"send", "fuzz", "expect", "capture", "sleep"}
    for i, raw_step in enumerate(raw_steps):
        if not isinstance(raw_step, dict) or len(raw_step) != 1:
            raise ScenarioError(
                f"scenario {section}[{i}] must be an object with a single step type"
            )
        step_type = next(iter(raw_step))
        if step_type not in valid_keys:
            raise ScenarioError(f"unsupported scenario step type: {step_type}")
        if section != "steps" and step_type == "fuzz":
            raise ScenarioError(f"scenario {section} cannot contain fuzz steps")
        _validate_step(cast(dict[str, Any], raw_step), section, i)
        steps.append(cast(dict[str, Any], raw_step))
    return steps


def _validate_dict_schema(
    data: dict[str, Any],
    required_keys: set[str] | None = None,
    optional_keys: set[str] | None = None,
    key_types: dict[str, type | tuple[type, ...]] | None = None,
    exactly_one: set[str] | None = None,
    path: str = "",
) -> None:
    required_keys = required_keys or set()
    optional_keys = optional_keys or set()
    key_types = key_types or {}

    if not isinstance(data, dict):
        raise ScenarioError(f"{path} must be an object")

    allowed_keys = required_keys | optional_keys
    if exactly_one is not None:
        allowed_keys |= exactly_one
    unsupported = set(data) - allowed_keys
    if unsupported:
        raise ScenarioError(f"unsupported {path} key: {min(unsupported)}")

    missing = required_keys - set(data)
    if missing:
        raise ScenarioError(f"{path} missing required key: {min(missing)}")

    if exactly_one is not None:
        present_from_exactly_one = set(data) & exactly_one
        if len(present_from_exactly_one) != 1:
            raise ScenarioError(
                f"{path} must define exactly one of: {', '.join(sorted(exactly_one))}"
            )

    for key, expected_type in key_types.items():
        if (
            key in data
            and data[key] is not None
            and not isinstance(data[key], expected_type)
        ):
            type_names = (
                "an object"
                if expected_type is dict
                else "an array"
                if expected_type is list
                else "a string"
                if expected_type is str
                else str(expected_type)
            )
            if isinstance(expected_type, tuple):
                type_names = " or ".join(
                    "an object"
                    if t is dict
                    else "an array"
                    if t is list
                    else "a string"
                    if t is str
                    else str(t)
                    for t in expected_type
                )
            raise ScenarioError(f"{path}.{key} must be {type_names}")


def _validate_connect(connect: dict[str, Any]) -> None:
    _validate_dict_schema(
        connect,
        optional_keys={"url", "path", "headers", "origin"},
        key_types={"url": str, "path": str, "origin": str, "headers": dict},
        path="scenario connect",
    )
    if "url" in connect and "path" in connect:
        raise ScenarioError("scenario connect cannot define both url and path")
    if "url" in connect and _VAR_RE.search(str(connect["url"])) is None:
        _validate_connect_url(str(connect["url"]))
    if "path" in connect:
        _validate_connect_path(str(connect["path"]))
    if "origin" in connect:
        origin = str(connect["origin"])
        if any(char in origin for char in "\r\n"):
            raise ScenarioError("scenario connect.origin must not contain newlines")
        if contains_control_chars(origin):
            raise ScenarioError(
                "scenario connect.origin must not contain control characters"
            )
    if "headers" in connect:
        if not isinstance(connect["headers"], dict):
            raise ScenarioError("scenario connect.headers must be an object")
        _validate_header_mapping(connect["headers"], "scenario connect.headers")


def _validate_pre_http(pre_http: dict[str, Any]) -> None:
    _validate_dict_schema(
        pre_http,
        required_keys={"url"},
        optional_keys={"method", "headers", "body", "expect_status", "capture"},
        key_types={
            "url": str,
            "method": str,
            "headers": dict,
            "body": (dict, list, str, type(None)),
            "capture": dict,
        },
        path="scenario pre_http",
    )
    if "method" in pre_http and not is_http_token(str(pre_http["method"])):
        raise ScenarioError("scenario pre_http.method must be a valid HTTP token")
    pre_http_url_text = str(pre_http["url"])
    _validate_uri_chars(pre_http_url_text, "scenario pre_http.url")
    pre_http_url = _split_url(pre_http_url_text, "scenario pre_http.url")
    if pre_http_url.fragment:
        raise ScenarioError("scenario pre_http.url must not contain fragments")
    if pre_http_url.scheme not in {"http", "https"} or not pre_http_url.netloc:
        raise ScenarioError("scenario pre_http.url must be an http:// or https:// URL")
    _validate_url_authority(pre_http_url, "scenario pre_http.url")
    if "headers" in pre_http:
        if not isinstance(pre_http["headers"], dict):
            raise ScenarioError("scenario pre_http.headers must be an object")
        _validate_header_mapping(pre_http["headers"], "scenario pre_http.headers")
    if "capture" in pre_http:
        capture = pre_http["capture"]
        if not isinstance(capture, dict):
            raise ScenarioError("scenario pre_http.capture must be an object")
        unsupported_capture = set(capture) - {"json", "headers"}
        if unsupported_capture:
            raise ScenarioError(
                f"unsupported scenario pre_http.capture key: {min(unsupported_capture)}"
            )
        for key in ("json", "headers"):
            if key in capture and not isinstance(capture[key], dict):
                raise ScenarioError(
                    f"scenario pre_http.capture.{key} must be an object"
                )
    if "expect_status" in pre_http:
        expect_status = _parse_integer(
            pre_http["expect_status"],
            "scenario pre_http.expect_status",
        )
        if not 100 <= expect_status <= 599:
            raise ScenarioError(
                "scenario pre_http.expect_status must be between 100 and 599"
            )
    if (
        "body" in pre_http
        and pre_http["body"] is not None
        and not isinstance(pre_http["body"], (dict, list, str))
    ):
        raise ScenarioError("scenario pre_http body must be a string, list, or object")


def _validate_header_mapping(headers: Any, context: str) -> None:
    if not isinstance(headers, dict):
        raise ScenarioError(f"{context} must be an object")
    for key, value in headers.items():
        header_name = str(key).strip()
        header_value = str(value)
        if not header_name:
            raise ScenarioError(f"{context} names must not be empty")
        if str(key) != header_name:
            raise ScenarioError(f"{context} names must be valid HTTP tokens")
        if any(char in header_name + header_value for char in "\r\n"):
            raise ScenarioError(f"{context} must not contain newlines")
        if contains_control_chars(header_value):
            raise ScenarioError(f"{context} must not contain control characters")
        if not is_http_token(header_name):
            raise ScenarioError(f"{context} names must be valid HTTP tokens")


def _validate_step(step: dict[str, Any], section: str, index: int) -> None:
    if "expect" in step:
        if not isinstance(step["expect"], dict):
            raise ScenarioError(f"scenario {section}[{index}].expect must be an object")
        _validate_expectation_shape(step["expect"], section, index)
    if "capture" in step:
        if not isinstance(step["capture"], dict):
            raise ScenarioError(
                f"scenario {section}[{index}].capture must be an object"
            )
        _validate_capture_shape(step["capture"], section, index)
    if "sleep" in step:
        _parse_sleep_seconds(
            step["sleep"],
            f"scenario {section}[{index}].sleep",
        )
    if "fuzz" in step:
        template, fallback = _split_fuzz_step(step["fuzz"])
        if not _template_contains_fuzz(template):
            raise ScenarioError(
                f"scenario {section}[{index}].fuzz template must contain [FUZZ]"
            )
        if fallback is not None and _template_contains_fuzz(fallback):
            raise ScenarioError(
                f"scenario {section}[{index}].fuzz fallback cannot contain [FUZZ]"
            )


def _validate_single_key(
    obj: dict[str, Any],
    supported: set[str],
    context: str,
    kind: str,
) -> None:
    unsupported = set(obj) - supported
    if unsupported:
        raise ScenarioError(f"unsupported {context} key: {min(unsupported)}")
    if len(obj) != 1:
        raise ScenarioError(f"{context} must define exactly one {kind}")


def _validate_expectation_shape(
    expectation: dict[str, Any],
    section: str,
    index: int,
) -> None:
    _validate_single_key(
        expectation,
        {"contains", "equals", "regex", "json"},
        f"scenario {section}[{index}].expect",
        "assertion",
    )


def _validate_capture_shape(
    capture: dict[str, Any],
    section: str,
    index: int,
) -> None:
    _validate_single_key(
        capture,
        {"json", "regex"},
        f"scenario {section}[{index}].capture",
        "extractor",
    )
    if "json" in capture:
        json_capture = capture["json"]
        if not isinstance(json_capture, dict):
            raise ScenarioError(
                f"scenario {section}[{index}].capture.json must be an object"
            )
        json_keys = set(json_capture)
        if {"var", "path"} <= json_keys and json_keys != {"var", "path"}:
            raise ScenarioError(
                f"scenario {section}[{index}].capture.json var/path form cannot include extra keys"
            )
    if "regex" in capture:
        regex_capture = capture["regex"]
        if not isinstance(regex_capture, dict):
            raise ScenarioError(
                f"scenario {section}[{index}].capture.regex must be an object"
            )
        unsupported_regex = set(regex_capture) - {"var", "pattern", "group"}
        if unsupported_regex:
            raise ScenarioError(
                f"unsupported scenario {section}[{index}].capture.regex key: {min(unsupported_regex)}"
            )
        required = {"var", "pattern"}
        missing = required - set(regex_capture)
        if missing:
            raise ScenarioError(
                f"scenario {section}[{index}].capture.regex missing {min(missing)}"
            )
        if "group" in regex_capture:
            group = _parse_integer(
                regex_capture["group"],
                f"scenario {section}[{index}].capture.regex.group",
            )
            if group < 0:
                raise ScenarioError(
                    f"scenario {section}[{index}].capture.regex.group must be non-negative"
                )


def _parse_integer(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ScenarioError(f"{context} must be an integer")
    try:
        return int(value)
    except ValueError as exc:
        raise ScenarioError(f"{context} must be an integer") from exc


def _parse_sleep_seconds(value: Any, context: str) -> float:
    if isinstance(value, bool):
        raise ScenarioError(f"{context} must be a number")
    try:
        sleep_seconds = float(value)
    except (TypeError, ValueError) as exc:
        raise ScenarioError(f"{context} must be a number") from exc
    if not math.isfinite(sleep_seconds):
        raise ScenarioError(f"{context} must be finite")
    if sleep_seconds < 0:
        raise ScenarioError(f"{context} must be non-negative")
    return sleep_seconds


def _collect_fuzz_steps(steps: list[dict[str, Any]]) -> list[FuzzStep]:
    fuzz_steps: list[FuzzStep] = []
    for index, step in enumerate(steps):
        if "fuzz" not in step:
            continue
        fuzz_value = step["fuzz"]
        name = fuzz_value.get("name") if _is_fuzz_control_object(fuzz_value) else None
        if name is not None and not isinstance(name, str):
            raise ScenarioError("scenario fuzz step name must be a string")
        fuzz_steps.append(FuzzStep(index=index, ordinal=len(fuzz_steps), name=name))
    return fuzz_steps


def _template_contains_fuzz(template: Any) -> bool:
    if isinstance(template, str):
        return "[FUZZ]" in template
    if isinstance(template, dict):
        return any(_template_contains_fuzz(value) for value in template.values())
    if isinstance(template, list):
        return any(_template_contains_fuzz(value) for value in template)
    return False


def _resolve_connect(
    base_uri: str,
    base_opts: ConnectOpts | None,
    connect: dict[str, Any],
    variables: dict[str, Any],
) -> tuple[str, ConnectOpts | None]:
    uri = base_uri
    if "url" in connect:
        uri = _render_string(str(connect["url"]), variables)
        _validate_connect_url(uri)
    elif "path" in connect:
        base = urlsplit(base_uri)
        rendered_path = _render_string(str(connect["path"]), variables)
        _validate_connect_path(rendered_path)
        path = urlsplit(rendered_path)
        uri = urlunsplit(
            (
                base.scheme,
                base.netloc,
                path.path or base.path,
                path.query,
                path.fragment,
            )
        )

    headers = dict(base_opts.headers if base_opts else {})
    for key, value in (connect.get("headers") or {}).items():
        headers[str(key).strip()] = str(_render_value(value, variables, None, "text"))

    origin = base_opts.origin if base_opts else None
    if "origin" in connect:
        origin = _render_string(str(connect["origin"]), variables)

    try:
        resolved_opts = make_connect_opts(
            headers,
            origin,
            ca_file=base_opts.ca_file if base_opts else None,
            insecure=base_opts.insecure if base_opts else False,
        )
    except ValueError as exc:
        raise ScenarioError(str(exc)) from exc
    return uri, resolved_opts


def _validate_uri_chars(value: str, context: str) -> None:
    if any(char in value for char in "\r\n"):
        raise ScenarioError(f"{context} must not contain newlines")
    if any(char in value for char in " \t"):
        raise ScenarioError(f"{context} must not contain whitespace")
    if contains_control_chars(value):
        raise ScenarioError(f"{context} must not contain control characters")


def _validate_connect_path(path: str) -> None:
    _validate_uri_chars(path, "scenario connect.path")
    parsed = _split_url(path, "scenario connect.path")
    if parsed.scheme or parsed.netloc:
        raise ScenarioError("scenario connect.path must be a path, not a URL")
    if parsed.fragment:
        raise ScenarioError("scenario connect.path must not contain fragments")


def _validate_connect_url(uri: str) -> None:
    _validate_uri_chars(uri, "scenario connect.url")
    parsed = _split_url(uri, "scenario connect.url")
    if parsed.fragment:
        raise ScenarioError("scenario connect.url must not contain fragments")
    if parsed.scheme not in {"ws", "wss"} or not parsed.netloc:
        raise ScenarioError("scenario connect.url must be a ws:// or wss:// URL")
    _validate_url_authority(parsed, "scenario connect.url")


def _split_url(value: str, context: str) -> SplitResult:
    try:
        return urlsplit(value)
    except ValueError as exc:
        raise ScenarioError(f"{context} must be a valid URL") from exc


def _validate_url_authority(parsed: SplitResult, context: str) -> None:
    if parsed.username is not None or parsed.password is not None:
        raise ScenarioError(f"{context} must not contain userinfo")
    if parsed.hostname is None:
        raise ScenarioError(f"{context} must include a host")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ScenarioError(f"{context} port must be between 1 and 65535") from exc
    if port == 0:
        raise ScenarioError(f"{context} port must be between 1 and 65535")


async def _run_pre_http(
    scenario: Scenario,
    timeout: float,
    opts: ConnectOpts | None = None,
) -> dict[str, Any]:
    if not scenario.pre_http:
        return {}
    pre_http = scenario.pre_http
    method = str(pre_http.get("method", "GET")).upper()
    url = str(pre_http.get("url", ""))
    if not url:
        raise ScenarioError("scenario pre_http requires url")

    headers = {
        str(key).strip(): str(value)
        for key, value in (pre_http.get("headers") or {}).items()
    }
    data = None
    body = pre_http.get("body")
    if body is not None:
        if isinstance(body, (dict, list)):
            data = json.dumps(body, separators=(",", ":")).encode()
            headers.setdefault("Content-Type", "application/json")
        elif isinstance(body, str):
            data = body.encode()
        else:
            raise ScenarioError(
                "scenario pre_http body must be a string, list, or object"
            )

    try:
        ssl_context = _make_pre_http_ssl_context(url, opts)
        status, response_headers, response_body = await asyncio.to_thread(
            _http_request,
            method,
            url,
            headers,
            data,
            timeout,
            ssl_context,
        )
    except (URLError, OSError) as e:
        raise ScenarioError(f"pre_http failed: {e}") from e

    expected_status = _parse_integer(
        pre_http.get("expect_status", 200),
        "scenario pre_http.expect_status",
    )
    if status != expected_status:
        raise ScenarioError(f"pre_http returned {status}, expected {expected_status}")

    variables: dict[str, Any] = {}
    capture = pre_http.get("capture") or {}
    if "json" in capture:
        payload = _parse_json_text(
            response_body.decode(errors="replace"),
            "pre_http JSON capture",
        )
        for var_name, path in capture["json"].items():
            variables[str(var_name)] = _json_path_get(payload, str(path))
    if "headers" in capture:
        for var_name, header_name in capture["headers"].items():
            header_value = response_headers.get(str(header_name))
            if header_value is None:
                raise ScenarioError(
                    f"pre_http response missing header {str(header_name)!r}"
                )
            variables[str(var_name)] = header_value
    return variables


def _http_request(
    method: str,
    url: str,
    headers: dict[str, str],
    data: bytes | None,
    timeout: float,
    ssl_context: ssl.SSLContext | None = None,
) -> tuple[int, Any, bytes]:
    request = Request(url, method=method, headers=headers, data=data)
    kwargs: dict[str, Any] = {"timeout": timeout}
    if ssl_context is not None:
        kwargs["context"] = ssl_context
    try:
        with urlopen(request, **kwargs) as response:
            return response.status, response.headers, response.read()
    except HTTPError as response:
        return response.code, response.headers, response.read()


def _make_pre_http_ssl_context(
    url: str,
    opts: ConnectOpts | None,
) -> ssl.SSLContext | None:
    if urlsplit(url).scheme != "https":
        return None
    if opts and opts.insecure:
        return ssl._create_unverified_context()
    try:
        return ssl.create_default_context(cafile=opts.ca_file if opts else None)
    except OSError as exc:
        raise TransportConfigError(f"TLS configuration error: {exc}") from exc


async def _execute_steps(
    ws: Any,
    steps: list[dict[str, Any]],
    mode: str,
    timeout: float,
    variables: dict[str, Any],
    *,
    payload: bytes | None,
    active_fuzz_step: FuzzStep | None,
) -> bytes | None:
    last_response: bytes | None = None
    fuzz_ordinal = 0
    skip_response_steps = False

    for step in steps:
        if "sleep" in step:
            if skip_response_steps:
                continue
            await asyncio.sleep(_parse_sleep_seconds(step["sleep"], "scenario sleep"))
            continue
        if "send" in step:
            last_response = None
            skip_response_steps = False
            await ws.send(_serialize_message(step["send"], mode, variables, None))
            continue
        if "fuzz" in step:
            fuzz_value = step["fuzz"]
            fuzz_template, fallback = _split_fuzz_step(fuzz_value)
            last_response = None
            if (
                active_fuzz_step is not None
                and fuzz_ordinal == active_fuzz_step.ordinal
            ):
                await ws.send(
                    _serialize_message(fuzz_template, mode, variables, payload)
                )
                skip_response_steps = False
            elif fallback is not None:
                await ws.send(_serialize_message(fallback, mode, variables, None))
                skip_response_steps = False
            else:
                skip_response_steps = True
            fuzz_ordinal += 1
            continue
        if "expect" in step:
            if skip_response_steps:
                continue
            last_response = await _recv_message(ws, timeout)
            _validate_expectation(last_response, step["expect"], variables)
            continue
        if "capture" in step:
            if skip_response_steps:
                continue
            if last_response is None:
                raise ScenarioError("capture step requires a previous response")
            _apply_capture(step["capture"], last_response, variables)
    return last_response


async def _recv_message(ws: Any, timeout: float) -> bytes:
    async with asyncio.timeout(timeout):
        response = await ws.recv()
    if isinstance(response, str):
        return response.encode()
    return response


def _serialize_message(
    template: Any,
    mode: str,
    variables: dict[str, Any],
    fuzz_payload: bytes | None,
) -> str | bytes:
    rendered = _render_value(template, variables, fuzz_payload, mode)
    if isinstance(rendered, bytes):
        if mode == "text":
            return rendered.decode(errors="replace")
        return rendered
    if isinstance(rendered, (dict, list)):
        try:
            rendered = json.dumps(rendered, separators=(",", ":"), ensure_ascii=False)
        except TypeError as e:
            raise ScenarioError(
                "binary [FUZZ] values cannot be embedded inside structured templates"
            ) from e
    elif isinstance(rendered, (int, float, bool)) or rendered is None:
        rendered = json.dumps(rendered, separators=(",", ":"))
    elif not isinstance(rendered, str):
        raise ScenarioError("scenario messages must render to JSON-compatible values")
    if mode == "text":
        return rendered
    return rendered.encode()


def _render_value(
    value: Any,
    variables: dict[str, Any],
    fuzz_payload: bytes | None,
    mode: str,
) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _render_value(item, variables, fuzz_payload, mode)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_render_value(item, variables, fuzz_payload, mode) for item in value]
    if not isinstance(value, str):
        return value
    if value == "[FUZZ]":
        if fuzz_payload is None:
            raise ScenarioError("[FUZZ] used outside active fuzz step")
        if mode == "binary":
            return fuzz_payload
        return fuzz_payload.decode(errors="replace")
    full_var = _VAR_RE.fullmatch(value)
    if full_var:
        return _variable_value(variables, full_var.group(1))
    return _render_string(value, variables, fuzz_payload, mode)


def _render_string(
    value: str,
    variables: dict[str, Any],
    fuzz_payload: bytes | None = None,
    mode: str = "text",
) -> str:
    if "[FUZZ]" in value:
        if fuzz_payload is None:
            raise ScenarioError("[FUZZ] used outside active fuzz step")
        if mode == "binary":
            try:
                fuzz_text = fuzz_payload.decode()
            except UnicodeDecodeError as e:
                raise ScenarioError(
                    "binary [FUZZ] payload cannot be interpolated inside a text template"
                ) from e
        else:
            fuzz_text = fuzz_payload.decode(errors="replace")
        value = value.replace("[FUZZ]", fuzz_text)
    return _VAR_RE.sub(
        lambda match: str(_variable_value(variables, match.group(1))),
        value,
    )


def _variable_value(variables: dict[str, Any], name: str) -> Any:
    try:
        return variables[name]
    except KeyError as exc:
        raise ScenarioError(f"scenario variable {name!r} is not defined") from exc


def _split_fuzz_step(step: Any) -> tuple[Any, Any]:
    if _is_fuzz_control_object(step):
        if "template" not in step:
            raise ScenarioError("scenario fuzz step requires template")
        return step["template"], step.get("fallback")
    return step, None


def _is_fuzz_control_object(step: Any) -> bool:
    if not isinstance(step, dict):
        return False
    keys = set(step)
    return bool(keys & {"name", "fallback"}) and keys <= _FUZZ_CONTROL_KEYS


def _validate_expectation(
    response: bytes,
    expectation: Any,
    variables: dict[str, Any],
) -> None:
    if not isinstance(expectation, dict):
        raise ScenarioError("scenario expect step must be an object")
    response_text = response.decode(errors="replace")
    if "contains" in expectation:
        needle = _render_string(str(expectation["contains"]), variables)
        if needle not in response_text:
            raise ScenarioError(
                f"expected response containing {needle!r}, got {response_text!r}"
            )
    elif "equals" in expectation:
        expected = _render_string(str(expectation["equals"]), variables)
        if response_text != expected:
            raise ScenarioError(
                f"expected response {expected!r}, got {response_text!r}"
            )
    elif "regex" in expectation:
        pattern = _render_string(str(expectation["regex"]), variables)
        if _regex_search(pattern, response_text, "expect") is None:
            raise ScenarioError(
                f"expected response matching {pattern!r}, got {response_text!r}"
            )
    elif "json" in expectation:
        payload = _parse_json_text(response_text, "expect JSON")
        expected = _render_value(expectation["json"], variables, None, "text")
        if not _json_contains(payload, expected):
            raise ScenarioError(
                f"expected JSON containing {expected!r}, got {payload!r}"
            )
    else:
        raise ScenarioError("unsupported scenario expectation")


def _apply_capture(
    capture: Any,
    response: bytes,
    variables: dict[str, Any],
) -> None:
    if not isinstance(capture, dict):
        raise ScenarioError("scenario capture step must be an object")
    response_text = response.decode(errors="replace")
    if "json" in capture:
        payload = _parse_json_text(response_text, "capture JSON")
        json_capture = capture["json"]
        if isinstance(json_capture, dict) and {"var", "path"} <= set(json_capture):
            variables[str(json_capture["var"])] = _json_path_get(
                payload, str(json_capture["path"])
            )
            return
        for var_name, path in json_capture.items():
            variables[str(var_name)] = _json_path_get(payload, str(path))
        return
    if "regex" in capture:
        spec = capture["regex"]
        match = _regex_search(str(spec["pattern"]), response_text, "capture")
        if match is None:
            raise ScenarioError(f"capture regex did not match: {spec['pattern']!r}")
        group = _parse_integer(spec.get("group", 1), "scenario capture.regex.group")
        if group < 0:
            raise ScenarioError("scenario capture.regex.group must be non-negative")
        try:
            variables[str(spec["var"])] = match.group(group)
        except IndexError as exc:
            raise ScenarioError(
                f"capture regex group {group} is not available"
            ) from exc
        return
    raise ScenarioError("unsupported scenario capture")


def _regex_search(pattern: str, text: str, context: str) -> re.Match[str] | None:
    try:
        return re.search(pattern, text)
    except re.error as exc:
        raise ScenarioError(f"scenario {context} regex is invalid: {exc}") from exc


def _parse_json_text(text: str, context: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ScenarioError(f"scenario {context} response is not valid JSON") from exc


def _json_contains(actual: Any, expected: Any) -> bool:
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(
            key in actual and _json_contains(actual[key], value)
            for key, value in expected.items()
        )
    if isinstance(expected, list):
        return (
            isinstance(actual, list)
            and len(actual) >= len(expected)
            and all(
                _json_contains(actual[index], value)
                for index, value in enumerate(expected)
            )
        )
    return actual == expected


def _json_path_get(payload: Any, path: str) -> Any:
    current = payload
    for raw_part in path.split("."):
        if isinstance(current, list):
            try:
                index = int(raw_part)
            except ValueError as exc:
                raise ScenarioError(
                    f"JSON path {path!r} expected a list index, got {raw_part!r}"
                ) from exc
            try:
                current = current[index]
            except IndexError as exc:
                raise ScenarioError(
                    f"JSON path {path!r} index {index} is out of range"
                ) from exc
            continue
        if not isinstance(current, dict):
            raise ScenarioError(f"cannot descend into JSON path {path!r}")
        try:
            current = current[raw_part]
        except KeyError as exc:
            raise ScenarioError(f"JSON path {path!r} missing key {raw_part!r}") from exc
    return current


def scenario_requires_text_mode(scenario: Scenario) -> bool:
    return any(
        _template_requires_text_mode(_split_fuzz_step(step["fuzz"])[0])
        for step in scenario.steps
        if "fuzz" in step
    )


def _template_requires_text_mode(template: Any, *, nested: bool = False) -> bool:
    if isinstance(template, dict):
        return any(
            _template_requires_text_mode(value, nested=True)
            for value in template.values()
        )
    if isinstance(template, list):
        return any(
            _template_requires_text_mode(value, nested=True) for value in template
        )
    if not isinstance(template, str):
        return False
    if template == "[FUZZ]":
        return nested
    return "[FUZZ]" in template
