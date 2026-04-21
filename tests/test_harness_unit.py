"""Unit tests for harness.py internal helper functions.

Tests _parse_headers, _build_response, _apply_template, _marker_value,
_render_json_template_value, and _parse_json_template directly without
running a full HTTP server.
"""

import json
from http import HTTPStatus

import pytest

from wsfuzz.harness import (
    HarnessRequest,
    HarnessTemplateError,
    _apply_template,
    _build_response,
    _parse_headers,
    _parse_json_template,
    _render_json_template_value,
)

# ---------------------------------------------------------------------------
# _parse_headers
# ---------------------------------------------------------------------------


class TestParseHeaders:
    def test_basic_request(self):
        raw = b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*"
        result = _parse_headers(raw)
        assert result is not None
        request_line, headers = result
        assert request_line == "GET / HTTP/1.1"
        assert headers["host"] == ["example.com"]
        assert headers["accept"] == ["*/*"]

    def test_multiple_values_same_header(self):
        raw = b"POST / HTTP/1.1\r\nX-Val: a\r\nX-Val: b\r\nX-Val: c"
        result = _parse_headers(raw)
        assert result is not None
        _, headers = result
        assert headers["x-val"] == ["a", "b", "c"]

    def test_colon_in_value(self):
        raw = b"GET / HTTP/1.1\r\nLocation: http://example.com:8080/path"
        result = _parse_headers(raw)
        assert result is not None
        _, headers = result
        assert headers["location"] == ["http://example.com:8080/path"]

    def test_empty_value(self):
        raw = b"GET / HTTP/1.1\r\nX-Empty:"
        result = _parse_headers(raw)
        assert result is not None
        _, headers = result
        assert headers["x-empty"] == [""]

    def test_header_with_whitespace_value(self):
        raw = b"GET / HTTP/1.1\r\nX-Test:  spaced  "
        result = _parse_headers(raw)
        assert result is not None
        _, headers = result
        assert headers["x-test"] == ["spaced"]

    def test_empty_input_returns_none(self):
        assert _parse_headers(b"") is None

    def test_line_without_colon_returns_none(self):
        raw = b"GET / HTTP/1.1\r\nno-colon-here"
        assert _parse_headers(raw) is None

    def test_header_name_with_leading_space_returns_none(self):
        raw = b"GET / HTTP/1.1\r\n X-Bad: value"
        assert _parse_headers(raw) is None

    def test_header_name_with_trailing_space_returns_none(self):
        raw = b"GET / HTTP/1.1\r\nX-Bad : value"
        assert _parse_headers(raw) is None

    def test_empty_header_name_returns_none(self):
        raw = b"GET / HTTP/1.1\r\n: value"
        assert _parse_headers(raw) is None

    def test_control_char_in_value_returns_none(self):
        raw = b"GET / HTTP/1.1\r\nX-Test: val\x0bue"
        assert _parse_headers(raw) is None

    def test_keys_lowercased(self):
        raw = b"GET / HTTP/1.1\r\nContent-Type: text/plain"
        result = _parse_headers(raw)
        assert result is not None
        _, headers = result
        assert "content-type" in headers

    def test_invalid_token_header_name_returns_none(self):
        raw = b"GET / HTTP/1.1\r\nBad Header: value"
        assert _parse_headers(raw) is None

    def test_skips_blank_lines(self):
        raw = b"GET / HTTP/1.1\r\n\r\nX-After: value"
        result = _parse_headers(raw)
        assert result is not None
        _, headers = result
        assert headers["x-after"] == ["value"]


# ---------------------------------------------------------------------------
# _build_response
# ---------------------------------------------------------------------------


class TestBuildResponse:
    def test_basic_200(self):
        response = _build_response(HTTPStatus.OK, b"hello")
        assert b"HTTP/1.1 200 OK\r\n" in response
        assert b"Content-Length: 5\r\n" in response
        assert response.endswith(b"hello")

    def test_empty_body(self):
        response = _build_response(HTTPStatus.NO_CONTENT)
        assert b"Content-Length: 0\r\n" in response

    def test_custom_headers(self):
        response = _build_response(
            HTTPStatus.OK,
            b"data",
            headers={"X-Custom": "test"},
        )
        assert b"X-Custom: test\r\n" in response

    def test_custom_header_overrides_default(self):
        response = _build_response(
            HTTPStatus.OK,
            b"data",
            headers={"Content-Type": "application/json"},
        )
        assert b"Content-Type: application/json\r\n" in response
        assert response.count(b"Content-Type") == 1

    def test_404_status(self):
        response = _build_response(HTTPStatus.NOT_FOUND, b"not found")
        assert b"HTTP/1.1 404 Not Found\r\n" in response

    def test_body_after_double_crlf(self):
        response = _build_response(HTTPStatus.OK, b"body-data")
        _, _, body = response.partition(b"\r\n\r\n")
        assert body == b"body-data"

    def test_connection_close_header(self):
        response = _build_response(HTTPStatus.OK)
        assert b"Connection: close\r\n" in response


# ---------------------------------------------------------------------------
# _apply_template
# ---------------------------------------------------------------------------


def _make_request(
    body: bytes = b"fuzz-input",
    method: str = "POST",
    path: str = "/test",
    headers: dict | None = None,
    query: dict | None = None,
) -> HarnessRequest:
    return HarnessRequest(
        method=method,
        path=path,
        query=query or {},
        headers=headers or {},
        body=body,
    )


class TestApplyTemplate:
    def test_fuzz_only_binary(self):
        req = _make_request(b"\xff\x00\x01")
        result = _apply_template("[FUZZ]", req, "binary")
        assert result == b"\xff\x00\x01"

    def test_fuzz_only_text(self):
        req = _make_request(b"hello")
        result = _apply_template("[FUZZ]", req, "text")
        assert result == b"hello"

    def test_fuzz_embedded_in_text(self):
        req = _make_request(b"payload")
        result = _apply_template('{"data": "[FUZZ]"}', req, "text")
        assert result == b'{"data": "payload"}'

    def test_method_marker(self):
        req = _make_request(method="POST")
        result = _apply_template("[METHOD]", req, "text")
        assert result == b"POST"

    def test_path_marker(self):
        req = _make_request(path="/api/v1/users")
        result = _apply_template("[PATH]", req, "text")
        assert result == b"/api/v1/users"

    def test_header_marker(self):
        req = _make_request(headers={"x-token": ["secret123"]})
        result = _apply_template("[HEADER:x-token]", req, "text")
        assert result == b"secret123"

    def test_header_marker_missing(self):
        req = _make_request(headers={})
        result = _apply_template("[HEADER:x-missing]", req, "text")
        assert result == b""

    def test_headers_marker_multiple(self):
        req = _make_request(headers={"cookie": ["a=1", "b=2"]})
        result = _apply_template("[HEADERS:cookie]", req, "text")
        assert result == b"a=1,b=2"

    def test_query_marker(self):
        req = _make_request(query={"id": ["42"]})
        result = _apply_template("[QUERY:id]", req, "text")
        assert result == b"42"

    def test_query_marker_missing(self):
        req = _make_request(query={})
        result = _apply_template("[QUERY:missing]", req, "text")
        assert result == b""

    def test_queries_marker_multiple(self):
        req = _make_request(query={"tag": ["a", "b", "c"]})
        result = _apply_template("[QUERIES:tag]", req, "text")
        assert result == b"a,b,c"

    def test_multiple_markers(self):
        req = _make_request(b"data", method="POST", path="/api")
        result = _apply_template("[METHOD] [PATH] [FUZZ]", req, "text")
        assert result == b"POST /api data"

    def test_json_template_format(self):
        req = _make_request(b"val")
        result = _apply_template('{"key": "[FUZZ]"}', req, "text", "json")
        parsed = json.loads(result)
        assert parsed == {"key": "val"}

    def test_unsupported_format_raises(self):
        req = _make_request()
        with pytest.raises(HarnessTemplateError, match="unsupported"):
            _apply_template("[FUZZ]", req, "text", "xml")


# ---------------------------------------------------------------------------
# _parse_json_template
# ---------------------------------------------------------------------------


class TestParseJsonTemplate:
    def test_valid_json(self):
        result = _parse_json_template('{"key": "value"}')
        assert result == {"key": "value"}

    def test_array_json(self):
        result = _parse_json_template("[1, 2, 3]")
        assert result == [1, 2, 3]

    def test_invalid_json_raises(self):
        with pytest.raises(HarnessTemplateError, match="not valid JSON"):
            _parse_json_template("{invalid")

    def test_caching(self):
        """Same template string should return same parsed object (cached)."""
        template = '{"a": 1}'
        result1 = _parse_json_template(template)
        result2 = _parse_json_template(template)
        assert result1 is result2


# ---------------------------------------------------------------------------
# _render_json_template_value
# ---------------------------------------------------------------------------


class TestRenderJsonTemplateValue:
    def test_string_with_marker(self):
        req = _make_request(b"injected")
        result = _render_json_template_value("[FUZZ]", req, "text")
        assert result == "injected"

    def test_string_without_marker(self):
        req = _make_request(b"data")
        result = _render_json_template_value("plain text", req, "text")
        assert result == "plain text"

    def test_integer_passes_through(self):
        req = _make_request()
        assert _render_json_template_value(42, req, "text") == 42

    def test_boolean_passes_through(self):
        req = _make_request()
        val = True
        assert _render_json_template_value(val, req, "text") is True

    def test_none_passes_through(self):
        req = _make_request()
        assert _render_json_template_value(None, req, "text") is None

    def test_nested_dict(self):
        req = _make_request(b"val")
        template = {"outer": {"inner": "[FUZZ]"}}
        result = _render_json_template_value(template, req, "text")
        assert result == {"outer": {"inner": "val"}}

    def test_list(self):
        req = _make_request(b"item")
        template = ["first", "[FUZZ]", "third"]
        result = _render_json_template_value(template, req, "text")
        assert result == ["first", "item", "third"]

    def test_marker_in_key(self):
        req = _make_request(b"val", method="POST")
        template = {"[METHOD]": "value"}
        result = _render_json_template_value(template, req, "text")
        assert result == {"POST": "value"}

    def test_partial_marker_in_string(self):
        req = _make_request(b"data")
        result = _render_json_template_value("prefix-[FUZZ]-suffix", req, "text")
        assert result == "prefix-data-suffix"
