"""Unit tests for scenario.py pure helper functions.

Tests _json_path_get, _apply_capture, _validate_expectation, _json_contains,
_variable_value, _split_fuzz_step, _is_fuzz_control_object, _parse_json_text,
and _regex_search directly without running full scenario sessions.
"""

import json

import pytest

from wsfuzz.scenario import (
    ScenarioError,
    _apply_capture,
    _is_fuzz_control_object,
    _json_contains,
    _json_path_get,
    _parse_json_text,
    _regex_search,
    _render_value,
    _serialize_message,
    _split_fuzz_step,
    _validate_expectation,
    _variable_value,
)

# ---------------------------------------------------------------------------
# _json_path_get
# ---------------------------------------------------------------------------


class TestJsonPathGet:
    def test_simple_key(self):
        assert _json_path_get({"name": "alice"}, "name") == "alice"

    def test_nested_key(self):
        payload = {"user": {"name": "alice", "age": 30}}
        assert _json_path_get(payload, "user.name") == "alice"
        assert _json_path_get(payload, "user.age") == 30

    def test_deeply_nested(self):
        payload = {"a": {"b": {"c": {"d": 42}}}}
        assert _json_path_get(payload, "a.b.c.d") == 42

    def test_list_index(self):
        payload = {"items": ["zero", "one", "two"]}
        assert _json_path_get(payload, "items.1") == "one"

    def test_nested_list_index(self):
        payload = {"data": [{"id": 10}, {"id": 20}]}
        assert _json_path_get(payload, "data.1.id") == 20

    def test_list_first_element(self):
        payload = [100, 200, 300]
        assert _json_path_get(payload, "0") == 100

    def test_missing_key_raises(self):
        with pytest.raises(ScenarioError, match="missing key"):
            _json_path_get({"a": 1}, "b")

    def test_missing_nested_key_raises(self):
        with pytest.raises(ScenarioError, match="missing key 'z'"):
            _json_path_get({"a": {"b": 1}}, "a.z")

    def test_non_integer_list_index_raises(self):
        with pytest.raises(ScenarioError, match="expected a list index"):
            _json_path_get([1, 2, 3], "abc")

    def test_list_index_out_of_range_raises(self):
        with pytest.raises(ScenarioError, match="out of range"):
            _json_path_get([1, 2], "5")

    def test_descend_into_scalar_raises(self):
        with pytest.raises(ScenarioError, match="cannot descend"):
            _json_path_get({"a": 42}, "a.b")

    def test_descend_into_string_raises(self):
        with pytest.raises(ScenarioError, match="cannot descend"):
            _json_path_get({"a": "hello"}, "a.length")

    def test_negative_list_index(self):
        # Python supports negative indexing, so -1 should work
        assert _json_path_get([10, 20, 30], "-1") == 30

    def test_returns_entire_subtree(self):
        payload = {"nested": {"a": 1, "b": 2}}
        result = _json_path_get(payload, "nested")
        assert result == {"a": 1, "b": 2}

    def test_returns_list_subtree(self):
        payload = {"items": [1, 2, 3]}
        assert _json_path_get(payload, "items") == [1, 2, 3]

    def test_null_value(self):
        assert _json_path_get({"key": None}, "key") is None

    def test_boolean_value(self):
        assert _json_path_get({"flag": True}, "flag") is True
        assert _json_path_get({"flag": False}, "flag") is False


# ---------------------------------------------------------------------------
# _apply_capture
# ---------------------------------------------------------------------------


class TestApplyCapture:
    def test_json_single_path(self):
        variables: dict = {}
        _apply_capture(
            {"json": {"token": "data.token"}},
            b'{"data": {"token": "abc123"}}',
            variables,
        )
        assert variables["token"] == "abc123"

    def test_json_multiple_paths(self):
        variables: dict = {}
        _apply_capture(
            {"json": {"name": "user.name", "id": "user.id"}},
            b'{"user": {"name": "alice", "id": 42}}',
            variables,
        )
        assert variables["name"] == "alice"
        assert variables["id"] == 42

    def test_json_var_path_form(self):
        """The {var, path} single-capture shorthand."""
        variables: dict = {}
        _apply_capture(
            {"json": {"var": "token", "path": "auth.token"}},
            b'{"auth": {"token": "xyz"}}',
            variables,
        )
        assert variables["token"] == "xyz"

    def test_regex_default_group(self):
        variables: dict = {}
        _apply_capture(
            {"regex": {"pattern": r"token=(\w+)", "var": "tok"}},
            b"session token=abc123 active",
            variables,
        )
        assert variables["tok"] == "abc123"

    def test_regex_explicit_group(self):
        variables: dict = {}
        _apply_capture(
            {"regex": {"pattern": r"(\w+)=(\w+)", "var": "val", "group": 2}},
            b"key=value",
            variables,
        )
        assert variables["val"] == "value"

    def test_regex_group_zero_full_match(self):
        variables: dict = {}
        _apply_capture(
            {"regex": {"pattern": r"\d+", "var": "num", "group": 0}},
            b"count: 42 items",
            variables,
        )
        assert variables["num"] == "42"

    def test_regex_no_match_raises(self):
        with pytest.raises(ScenarioError, match="did not match"):
            _apply_capture(
                {"regex": {"pattern": r"NOTFOUND", "var": "x"}},
                b"some response",
                {},
            )

    def test_regex_invalid_group_raises(self):
        with pytest.raises(ScenarioError, match="group 5 is not available"):
            _apply_capture(
                {"regex": {"pattern": r"(\w+)", "var": "x", "group": 5}},
                b"hello",
                {},
            )

    def test_regex_negative_group_raises(self):
        with pytest.raises(ScenarioError, match="non-negative"):
            _apply_capture(
                {"regex": {"pattern": r"(\w+)", "var": "x", "group": -1}},
                b"hello",
                {},
            )

    def test_invalid_regex_raises(self):
        with pytest.raises(ScenarioError, match="regex is invalid"):
            _apply_capture(
                {"regex": {"pattern": r"[invalid", "var": "x"}},
                b"hello",
                {},
            )

    def test_non_dict_capture_raises(self):
        with pytest.raises(ScenarioError, match="must be an object"):
            _apply_capture("not a dict", b"response", {})

    def test_unsupported_capture_type_raises(self):
        with pytest.raises(ScenarioError, match="unsupported"):
            _apply_capture({"xpath": "/root"}, b"<root/>", {})

    def test_invalid_json_response_raises(self):
        with pytest.raises(ScenarioError, match="not valid JSON"):
            _apply_capture(
                {"json": {"key": "val"}},
                b"not json",
                {},
            )

    def test_capture_overwrites_existing_variable(self):
        variables = {"tok": "old"}
        _apply_capture(
            {"regex": {"pattern": r"(\w+)", "var": "tok"}},
            b"new_value",
            variables,
        )
        assert variables["tok"] == "new_value"


# ---------------------------------------------------------------------------
# _validate_expectation
# ---------------------------------------------------------------------------


class TestValidateExpectation:
    def test_contains_pass(self):
        # Should not raise
        _validate_expectation(b"hello world", {"contains": "world"}, {})

    def test_contains_fail(self):
        with pytest.raises(ScenarioError, match="expected response containing"):
            _validate_expectation(b"hello", {"contains": "world"}, {})

    def test_equals_pass(self):
        _validate_expectation(b"exact match", {"equals": "exact match"}, {})

    def test_equals_fail(self):
        with pytest.raises(ScenarioError, match="expected response"):
            _validate_expectation(b"actual", {"equals": "expected"}, {})

    def test_regex_pass(self):
        _validate_expectation(b"order 12345", {"regex": r"\d{5}"}, {})

    def test_regex_fail(self):
        with pytest.raises(ScenarioError, match="expected response matching"):
            _validate_expectation(b"no digits here", {"regex": r"\d+"}, {})

    def test_json_pass(self):
        _validate_expectation(
            b'{"status": "ok", "count": 5}',
            {"json": {"status": "ok"}},
            {},
        )

    def test_json_fail(self):
        with pytest.raises(ScenarioError, match="expected JSON containing"):
            _validate_expectation(
                b'{"status": "error"}',
                {"json": {"status": "ok"}},
                {},
            )

    def test_non_dict_expectation_raises(self):
        with pytest.raises(ScenarioError, match="must be an object"):
            _validate_expectation(b"data", "not a dict", {})

    def test_unsupported_expectation_raises(self):
        with pytest.raises(ScenarioError, match="unsupported"):
            _validate_expectation(b"data", {"xpath": "/root"}, {})

    def test_invalid_json_response_raises(self):
        with pytest.raises(ScenarioError, match="not valid JSON"):
            _validate_expectation(b"not json", {"json": {"key": "val"}}, {})

    def test_contains_with_variable(self):
        variables = {"expected": "world"}
        _validate_expectation(b"hello world", {"contains": "${expected}"}, variables)

    def test_regex_with_variable(self):
        variables = {"pat": r"\d+"}
        _validate_expectation(b"count: 42", {"regex": "${pat}"}, variables)

    def test_invalid_regex_in_expectation_raises(self):
        with pytest.raises(ScenarioError, match="regex is invalid"):
            _validate_expectation(b"data", {"regex": "[unclosed"}, {})

    def test_json_nested_subset(self):
        """JSON expectation should match nested subsets."""
        response = json.dumps(
            {"user": {"name": "alice", "role": "admin"}, "extra": True}
        ).encode()
        _validate_expectation(response, {"json": {"user": {"name": "alice"}}}, {})

    def test_json_list_prefix(self):
        """JSON expectation should match list prefixes."""
        response = json.dumps([1, 2, 3, 4]).encode()
        _validate_expectation(response, {"json": [1, 2]}, {})


# ---------------------------------------------------------------------------
# _json_contains
# ---------------------------------------------------------------------------


class TestJsonContains:
    def test_equal_scalars(self):
        assert _json_contains(42, 42) is True
        assert _json_contains("hello", "hello") is True
        true_val = True
        assert _json_contains(true_val, true_val) is True
        assert _json_contains(None, None) is True

    def test_unequal_scalars(self):
        assert _json_contains(42, 43) is False
        assert _json_contains("hello", "world") is False

    def test_dict_subset(self):
        actual = {"a": 1, "b": 2, "c": 3}
        assert _json_contains(actual, {"a": 1, "b": 2}) is True

    def test_dict_extra_key_in_expected(self):
        actual = {"a": 1}
        assert _json_contains(actual, {"a": 1, "b": 2}) is False

    def test_nested_dict_subset(self):
        actual = {"user": {"name": "alice", "age": 30}, "active": True}
        assert _json_contains(actual, {"user": {"name": "alice"}}) is True

    def test_list_prefix(self):
        assert _json_contains([1, 2, 3], [1, 2]) is True

    def test_list_too_short(self):
        assert _json_contains([1], [1, 2]) is False

    def test_list_wrong_element(self):
        assert _json_contains([1, 2, 3], [1, 99]) is False

    def test_empty_dict_matches_any_dict(self):
        assert _json_contains({"a": 1}, {}) is True

    def test_empty_list_matches_any_list(self):
        assert _json_contains([1, 2, 3], []) is True

    def test_type_mismatch(self):
        assert _json_contains("string", {"key": "val"}) is False
        assert _json_contains(42, [42]) is False


# ---------------------------------------------------------------------------
# _variable_value
# ---------------------------------------------------------------------------


class TestVariableValue:
    def test_existing_variable(self):
        assert _variable_value({"x": 42}, "x") == 42

    def test_missing_variable_raises(self):
        with pytest.raises(ScenarioError, match="not defined"):
            _variable_value({}, "missing")

    def test_none_value_returned(self):
        assert _variable_value({"x": None}, "x") is None


# ---------------------------------------------------------------------------
# _split_fuzz_step
# ---------------------------------------------------------------------------


class TestSplitFuzzStep:
    def test_plain_string_returns_template_and_none(self):
        template, fallback = _split_fuzz_step("[FUZZ]")
        assert template == "[FUZZ]"
        assert fallback is None

    def test_plain_dict_without_control_keys(self):
        step = {"key": "value"}
        template, fallback = _split_fuzz_step(step)
        assert template == step
        assert fallback is None

    def test_control_object_with_fallback(self):
        step = {"name": "test", "template": "[FUZZ]", "fallback": "default"}
        template, fallback = _split_fuzz_step(step)
        assert template == "[FUZZ]"
        assert fallback == "default"

    def test_control_object_without_fallback(self):
        step = {"name": "test", "template": "[FUZZ]"}
        template, fallback = _split_fuzz_step(step)
        assert template == "[FUZZ]"
        assert fallback is None

    def test_control_object_missing_template_raises(self):
        with pytest.raises(ScenarioError, match="requires template"):
            _split_fuzz_step({"name": "test"})


# ---------------------------------------------------------------------------
# _is_fuzz_control_object
# ---------------------------------------------------------------------------


class TestIsFuzzControlObject:
    def test_non_dict(self):
        assert _is_fuzz_control_object("[FUZZ]") is False
        assert _is_fuzz_control_object(42) is False

    def test_regular_message_dict(self):
        # Dict with only "template" is a regular message, not control
        assert _is_fuzz_control_object({"template": "[FUZZ]"}) is False

    def test_dict_with_name_is_control(self):
        assert _is_fuzz_control_object({"name": "test", "template": "[FUZZ]"}) is True

    def test_dict_with_fallback_is_control(self):
        assert _is_fuzz_control_object({"fallback": "x", "template": "[FUZZ]"}) is True

    def test_dict_with_unrelated_keys_not_control(self):
        assert _is_fuzz_control_object({"action": "login"}) is False

    def test_dict_with_extra_keys_not_control(self):
        # Keys outside _FUZZ_CONTROL_KEYS disqualify
        assert (
            _is_fuzz_control_object({"name": "x", "template": "y", "extra": "z"})
            is False
        )


# ---------------------------------------------------------------------------
# _parse_json_text
# ---------------------------------------------------------------------------


class TestParseJsonText:
    def test_valid_json(self):
        assert _parse_json_text('{"a": 1}', "test") == {"a": 1}

    def test_valid_json_array(self):
        assert _parse_json_text("[1, 2, 3]", "test") == [1, 2, 3]

    def test_invalid_json_raises(self):
        with pytest.raises(ScenarioError, match="not valid JSON"):
            _parse_json_text("not json at all", "test context")

    def test_empty_string_raises(self):
        with pytest.raises(ScenarioError, match="not valid JSON"):
            _parse_json_text("", "test")


# ---------------------------------------------------------------------------
# _regex_search
# ---------------------------------------------------------------------------


class TestRegexSearch:
    def test_matching_pattern(self):
        match = _regex_search(r"\d+", "abc 123 def", "test")
        assert match is not None
        assert match.group() == "123"

    def test_no_match(self):
        assert _regex_search(r"\d+", "no digits", "test") is None

    def test_invalid_regex_raises(self):
        with pytest.raises(ScenarioError, match="regex is invalid"):
            _regex_search(r"[unclosed", "text", "test context")


# ---------------------------------------------------------------------------
# _render_value / _serialize_message edge cases
# ---------------------------------------------------------------------------


class TestRenderValueEdgeCases:
    def test_integer_passes_through(self):
        assert _render_value(42, {}, None, "text") == 42

    def test_float_passes_through(self):
        assert _render_value(3.14, {}, None, "text") == 3.14

    def test_bool_passes_through(self):
        val = True
        assert _render_value(val, {}, None, "text") is True

    def test_none_passes_through(self):
        assert _render_value(None, {}, None, "text") is None

    def test_fuzz_none_payload_raises(self):
        with pytest.raises(ScenarioError, match=r"\[FUZZ\] used outside"):
            _render_value("[FUZZ]", {}, None, "text")

    def test_binary_fuzz_in_text_template_with_invalid_utf8_raises(self):
        with pytest.raises(ScenarioError, match="cannot be interpolated"):
            _render_value("prefix [FUZZ] suffix", {}, b"\xff\xfe", "binary")

    def test_text_fuzz_replaces_with_lossy_decode(self):
        result = _render_value("data: [FUZZ]", {}, b"\xff\xfe", "text")
        assert "data: " in result
        # Invalid bytes replaced, not raised
        assert "\ufffd" in result

    def test_full_var_returns_non_string_type(self):
        """A full ${var} match returns the variable's actual type."""
        variables = {"count": 42}
        result = _render_value("${count}", variables, None, "text")
        assert result == 42
        assert isinstance(result, int)

    def test_embedded_var_stringified(self):
        """Variable embedded in text is stringified."""
        variables = {"n": 42}
        result = _render_value("count is ${n}", variables, None, "text")
        assert result == "count is 42"

    def test_dict_keys_stringified(self):
        """Dict keys with non-string types become strings."""
        template = {42: "value"}
        result = _render_value(template, {}, None, "text")
        assert "42" in result

    def test_empty_list(self):
        assert _render_value([], {}, None, "text") == []

    def test_empty_dict(self):
        assert _render_value({}, {}, None, "text") == {}


class TestSerializeMessageEdgeCases:
    def test_int_serializes_to_json_string(self):
        msg = _serialize_message(42, "text", {}, None)
        assert msg == "42"

    def test_bool_serializes_to_json_string(self):
        val = True
        msg = _serialize_message(val, "text", {}, None)
        assert msg == "true"

    def test_none_serializes_to_json_string(self):
        msg = _serialize_message(None, "text", {}, None)
        assert msg == "null"

    def test_float_serializes_to_json_string(self):
        msg = _serialize_message(3.14, "text", {}, None)
        assert isinstance(msg, str)
        assert "3.14" in msg

    def test_dict_serializes_to_compact_json_text_mode(self):
        msg = _serialize_message({"a": 1}, "text", {}, None)
        assert isinstance(msg, str)
        parsed = json.loads(msg)
        assert parsed == {"a": 1}

    def test_dict_serializes_to_bytes_binary_mode(self):
        msg = _serialize_message({"a": 1}, "binary", {}, None)
        assert isinstance(msg, bytes)
        parsed = json.loads(msg)
        assert parsed == {"a": 1}

    def test_bare_fuzz_binary_returns_raw_bytes(self):
        msg = _serialize_message("[FUZZ]", "binary", {}, b"\xff\x00")
        assert msg == b"\xff\x00"

    def test_bare_fuzz_text_returns_string(self):
        msg = _serialize_message("[FUZZ]", "text", {}, b"hello")
        assert msg == "hello"
        assert isinstance(msg, str)

    def test_binary_fuzz_in_dict_template_raises(self):
        """Binary [FUZZ] embedded in a dict can't be JSON-serialized."""
        with pytest.raises(ScenarioError, match=r"binary.*cannot be embedded"):
            _serialize_message({"data": "[FUZZ]"}, "binary", {}, b"\xff\x00")
