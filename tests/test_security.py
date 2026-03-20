"""Security tests: verify the fuzzer detects real vulnerability classes.

Each test targets a specific vulnerability in the vulnerable_server.py
by sending a known-bad payload through the transport layer and checking
that the result is classified as interesting (crash-worthy). Then integration
tests run the full fuzzer and verify crash files are produced.
"""

import asyncio
from pathlib import Path

from wsfuzz.fuzzer import FuzzConfig, run
from wsfuzz.logger import CrashLogger
from wsfuzz.transport import send_payload

# ---------------------------------------------------------------------------
# Direct transport tests — known-bad payloads against specific vulnerabilities
# ---------------------------------------------------------------------------


class TestJsonParseCrash:
    """Server crashes on malformed JSON — unhandled ValueError/JSONDecodeError."""

    def test_malformed_json_triggers_error(self, vuln_server):
        payload = b"{not valid json!!!}"
        result = asyncio.run(
            send_payload(vuln_server + "/json-parse", payload, "text", 5.0)
        )
        assert result.error is not None

    def test_truncated_json(self, vuln_server):
        payload = b'{"key": "value'  # missing closing brace
        result = asyncio.run(
            send_payload(vuln_server + "/json-parse", payload, "text", 5.0)
        )
        assert result.error is not None

    def test_empty_input(self, vuln_server):
        payload = b""
        result = asyncio.run(
            send_payload(vuln_server + "/json-parse", payload, "text", 5.0)
        )
        # Empty text frame should crash json.loads
        assert result.error is not None or result.response is not None

    def test_valid_json_succeeds(self, vuln_server):
        payload = b'{"key": "value"}'
        result = asyncio.run(
            send_payload(vuln_server + "/json-parse", payload, "text", 5.0)
        )
        assert result.error is None
        assert result.response is not None
        assert b"ok" in result.response

    def test_is_classified_as_interesting(self, vuln_server):
        payload = b"not json"
        result = asyncio.run(
            send_payload(vuln_server + "/json-parse", payload, "text", 5.0)
        )
        logger = CrashLogger(Path("/tmp/unused"))
        assert logger.is_interesting(result) is True


class TestBufferOverflow:
    """Server crashes on payloads exceeding 128 bytes."""

    def test_small_payload_ok(self, vuln_server):
        payload = b"A" * 64
        result = asyncio.run(
            send_payload(vuln_server + "/overflow", payload, "binary", 5.0)
        )
        assert result.error is None
        assert result.response == payload

    def test_boundary_payload_ok(self, vuln_server):
        payload = b"A" * 128
        result = asyncio.run(
            send_payload(vuln_server + "/overflow", payload, "binary", 5.0)
        )
        assert result.error is None

    def test_oversized_payload_crashes(self, vuln_server):
        payload = b"A" * 129
        result = asyncio.run(
            send_payload(vuln_server + "/overflow", payload, "binary", 5.0)
        )
        assert result.error is not None

    def test_large_payload_crashes(self, vuln_server):
        payload = b"A" * 4096
        result = asyncio.run(
            send_payload(vuln_server + "/overflow", payload, "binary", 5.0)
        )
        assert result.error is not None
        logger = CrashLogger(Path("/tmp/unused"))
        assert logger.is_interesting(result) is True


class TestFormatString:
    """Server uses user input as format template — crashes on unresolved placeholders."""

    def test_normal_text_ok(self, vuln_server):
        payload = b"hello world"
        result = asyncio.run(
            send_payload(vuln_server + "/format-string", payload, "text", 5.0)
        )
        assert result.error is None
        assert result.response == b"hello world"

    def test_format_placeholder_crashes(self, vuln_server):
        payload = b"{missing_key}"
        result = asyncio.run(
            send_payload(vuln_server + "/format-string", payload, "text", 5.0)
        )
        # KeyError from .format() — server crashes
        assert result.error is not None

    def test_format_index_crashes(self, vuln_server):
        payload = b"{0}{1}{2}"
        result = asyncio.run(
            send_payload(vuln_server + "/format-string", payload, "text", 5.0)
        )
        assert result.error is not None

    def test_known_placeholders_resolve(self, vuln_server):
        payload = b"hello {user}"
        result = asyncio.run(
            send_payload(vuln_server + "/format-string", payload, "text", 5.0)
        )
        assert result.error is None
        assert result.response == b"hello admin"

    def test_attribute_access_info_leak(self, vuln_server):
        payload = b"{user.__class__}"
        result = asyncio.run(
            send_payload(vuln_server + "/format-string", payload, "text", 5.0)
        )
        # May succeed (info leak) or crash — either way it's a security issue
        if result.error is None:
            assert result.response is not None
            assert b"str" in result.response  # leaked type info


class TestNullByteInjection:
    """Server splits on null byte without bounds checking."""

    def test_with_null_byte_succeeds(self, vuln_server):
        payload = b"first\x00second"
        result = asyncio.run(
            send_payload(vuln_server + "/null-byte", payload, "text", 5.0)
        )
        assert result.error is None
        assert result.response is not None
        assert b"first" in result.response
        assert b"second" in result.response

    def test_without_null_byte_crashes(self, vuln_server):
        payload = b"no null byte here"
        result = asyncio.run(
            send_payload(vuln_server + "/null-byte", payload, "text", 5.0)
        )
        # IndexError: list index out of range — parts[1] doesn't exist
        assert result.error is not None

    def test_only_null_byte(self, vuln_server):
        payload = b"\x00"
        result = asyncio.run(
            send_payload(vuln_server + "/null-byte", payload, "text", 5.0)
        )
        assert result.error is None  # splits into ["", ""]

    def test_multiple_null_bytes(self, vuln_server):
        payload = b"a\x00b\x00c\x00d"
        result = asyncio.run(
            send_payload(vuln_server + "/null-byte", payload, "text", 5.0)
        )
        assert result.error is None


class TestIntegerOverflow:
    """Server crashes on non-integer or out-of-range integer input."""

    def test_valid_integer(self, vuln_server):
        payload = b"42"
        result = asyncio.run(
            send_payload(vuln_server + "/int-overflow", payload, "text", 5.0)
        )
        assert result.error is None
        assert result.response == b"\x00\x00\x00\x2a"

    def test_non_numeric_crashes(self, vuln_server):
        payload = b"not a number"
        result = asyncio.run(
            send_payload(vuln_server + "/int-overflow", payload, "text", 5.0)
        )
        assert result.error is not None

    def test_overflow_crashes(self, vuln_server):
        payload = b"9999999999999999999"
        result = asyncio.run(
            send_payload(vuln_server + "/int-overflow", payload, "text", 5.0)
        )
        # struct.pack(">i", huge_number) raises struct.error
        assert result.error is not None

    def test_negative_overflow(self, vuln_server):
        payload = b"-9999999999999999999"
        result = asyncio.run(
            send_payload(vuln_server + "/int-overflow", payload, "text", 5.0)
        )
        assert result.error is not None

    def test_float_crashes(self, vuln_server):
        payload = b"3.14"
        result = asyncio.run(
            send_payload(vuln_server + "/int-overflow", payload, "text", 5.0)
        )
        assert result.error is not None


class TestTypeConfusion:
    """Server expects JSON dict with specific keys — crashes on wrong types."""

    def test_valid_object(self, vuln_server):
        payload = b'{"name": "alice", "action": "login"}'
        result = asyncio.run(
            send_payload(vuln_server + "/type-confusion", payload, "text", 5.0)
        )
        assert result.error is None
        assert result.response is not None
        assert b"alice" in result.response

    def test_array_instead_of_object(self, vuln_server):
        payload = b"[1, 2, 3]"
        result = asyncio.run(
            send_payload(vuln_server + "/type-confusion", payload, "text", 5.0)
        )
        # TypeError: list indices must be integers, not str
        assert result.error is not None

    def test_string_instead_of_object(self, vuln_server):
        payload = b'"just a string"'
        result = asyncio.run(
            send_payload(vuln_server + "/type-confusion", payload, "text", 5.0)
        )
        assert result.error is not None

    def test_missing_keys(self, vuln_server):
        payload = b'{"name": "alice"}'  # missing "action"
        result = asyncio.run(
            send_payload(vuln_server + "/type-confusion", payload, "text", 5.0)
        )
        assert result.error is not None

    def test_null_values(self, vuln_server):
        payload = b'{"name": null, "action": null}'
        result = asyncio.run(
            send_payload(vuln_server + "/type-confusion", payload, "text", 5.0)
        )
        # Succeeds but with None — f-string handles it
        assert result.error is None


# ---------------------------------------------------------------------------
# Fuzzer integration tests — run the full fuzzer, verify crashes are logged
# ---------------------------------------------------------------------------


class TestFuzzerFindsVulnerabilities:
    """Run the actual fuzzer against vulnerable endpoints and verify it logs crashes."""

    def test_fuzzer_finds_json_crashes(self, vuln_server, tmp_path, capsys):
        config = FuzzConfig(
            target=vuln_server + "/json-parse",
            mode="text",
            iterations=20,
            max_size=200,
            timeout=2.0,
            log_dir=tmp_path / "crashes",
        )
        run(config)
        out = capsys.readouterr().out
        crash_files = list((tmp_path / "crashes").glob("crash_*.bin"))
        # Radamsa mutations of our seeds are very unlikely to produce valid JSON
        assert len(crash_files) > 0, f"fuzzer should find JSON parse crashes\n{out}"

    def test_fuzzer_finds_overflow(self, vuln_server, tmp_path, capsys):
        config = FuzzConfig(
            target=vuln_server + "/overflow",
            mode="binary",
            iterations=20,
            max_size=256,  # larger than the 128-byte limit
            timeout=2.0,
            log_dir=tmp_path / "crashes",
        )
        run(config)
        crash_files = list((tmp_path / "crashes").glob("crash_*.bin"))
        # Most random/mutated payloads will exceed 128 bytes with max_size=256
        assert len(crash_files) > 0, "fuzzer should find buffer overflow crashes"

    def test_fuzzer_finds_format_string_bugs(self, vuln_server, tmp_path, capsys):
        # Create a seed corpus with format-string-like payloads
        seed_dir = tmp_path / "seeds"
        seed_dir.mkdir()
        (seed_dir / "fmt.txt").write_bytes(b"{key}{0}{1}")
        (seed_dir / "normal.txt").write_bytes(b"hello world test data")

        config = FuzzConfig(
            target=vuln_server + "/format-string",
            mode="text",
            seeds_dir=seed_dir,
            iterations=20,
            max_size=200,
            timeout=2.0,
            log_dir=tmp_path / "crashes",
        )
        run(config)
        crash_files = list((tmp_path / "crashes").glob("crash_*.bin"))
        assert len(crash_files) > 0, "fuzzer should find format string crashes"

    def test_fuzzer_finds_integer_bugs(self, vuln_server, tmp_path, capsys):
        seed_dir = tmp_path / "seeds"
        seed_dir.mkdir()
        (seed_dir / "nums.txt").write_bytes(b"42\n99999999\n-1\n0")
        (seed_dir / "big.txt").write_bytes(b"9999999999999999999999")

        config = FuzzConfig(
            target=vuln_server + "/int-overflow",
            mode="text",
            seeds_dir=seed_dir,
            iterations=20,
            max_size=200,
            timeout=2.0,
            log_dir=tmp_path / "crashes",
        )
        run(config)
        crash_files = list((tmp_path / "crashes").glob("crash_*.bin"))
        assert len(crash_files) > 0, "fuzzer should find integer overflow crashes"

    def test_fuzzer_finds_type_confusion(self, vuln_server, tmp_path, capsys):
        seed_dir = tmp_path / "seeds"
        seed_dir.mkdir()
        (seed_dir / "obj.txt").write_bytes(b'{"name":"a","action":"b"}')
        (seed_dir / "arr.txt").write_bytes(b"[1,2,3]")
        (seed_dir / "str.txt").write_bytes(b'"just a string"')

        config = FuzzConfig(
            target=vuln_server + "/type-confusion",
            mode="text",
            seeds_dir=seed_dir,
            iterations=20,
            max_size=200,
            timeout=2.0,
            log_dir=tmp_path / "crashes",
        )
        run(config)
        crash_files = list((tmp_path / "crashes").glob("crash_*.bin"))
        assert len(crash_files) > 0, "fuzzer should find type confusion crashes"

    def test_crash_files_contain_reproducibility_info(self, vuln_server, tmp_path):
        """Verify crash metadata includes the radamsa seed for reproduction."""
        config = FuzzConfig(
            target=vuln_server + "/json-parse",
            mode="text",
            iterations=10,
            timeout=2.0,
            log_dir=tmp_path / "crashes",
        )
        run(config)

        txt_files = list((tmp_path / "crashes").glob("crash_*.txt"))
        assert len(txt_files) > 0

        content = txt_files[0].read_text()
        assert "radamsa_seed:" in content
        assert "seed_index:" in content
        assert "error_type:" in content
        assert "payload_size:" in content

    def test_corpus_grows_on_crashes(self, vuln_server, tmp_path, capsys):
        """Verify that crash-triggering payloads are added back to the corpus."""
        # Provide large seeds so radamsa produces payloads > 128 bytes
        seeds_dir = tmp_path / "seeds"
        seeds_dir.mkdir()
        (seeds_dir / "large.bin").write_bytes(b"A" * 200)
        config = FuzzConfig(
            target=vuln_server + "/overflow",
            mode="binary",
            seeds_dir=seeds_dir,
            iterations=10,
            max_size=256,
            timeout=2.0,
            log_dir=tmp_path / "crashes",
            verbose=True,
        )
        run(config)
        out = capsys.readouterr().out
        crash_count = out.count("[CRASH]")
        # With max_size=256, large seeds, and a 128-byte limit, most payloads crash.
        assert crash_count > 0
