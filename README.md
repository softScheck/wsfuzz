# wsfuzz

Mutation-based WebSocket fuzzer. Uses [Radamsa](https://gitlab.com/akihe/radamsa) for input generation, async I/O for concurrency, and raw TCP for protocol-level frame fuzzing. It supports both simple connect-send-observe fuzzing and JSON-defined multi-step stateful scenarios.

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- [Radamsa](https://gitlab.com/akihe/radamsa)

## Install

```bash
uv sync
```

## Usage

```bash
# Basic fuzzing
wsfuzz -t ws://localhost:64999

# Text mode, 10 concurrent connections, 1000 iterations
wsfuzz -t ws://localhost:64999 -m text -c 10 -n 1000

# Raw mode — fuzz WebSocket frame headers (opcodes, RSV bits, masking, payload lengths)
wsfuzz -t ws://localhost:64999 --raw

# Also fuzz the HTTP upgrade handshake (Sec-WebSocket-Version, Extensions, Protocol)
wsfuzz -t ws://localhost:64999 --raw --fuzz-handshake

# Use a custom CA bundle for wss:// targets
wsfuzz -t wss://localhost:64999 --tls-ca ./certs/dev-ca.pem

# Disable TLS verification for lab targets with self-signed certs
wsfuzz -t wss://localhost:64999 --insecure

# Authenticated fuzzing with custom headers
wsfuzz -t ws://localhost:64999 -H "Cookie: session=abc" -H "Authorization: Bearer tok"

# CSWSH detection — test if server validates Origin
wsfuzz -t ws://localhost:64999 --origin http://evil.example.com

# Replay crashes for reproduction
wsfuzz -t ws://localhost:64999 --replay ./crashes

# Stateful scenario fuzzing with setup, capture, and one fuzz step per iteration
# Scenario mode defaults to text unless you explicitly pass -m
wsfuzz -t ws://localhost:64999 --scenario ./scenarios/orders.json

# Rotate across multiple fuzz points inside the scenario
wsfuzz -t ws://localhost:64999 --scenario ./scenarios/orders.json --scenario-fuzz-mode round-robin

# Reuse one authenticated WebSocket session across iterations
wsfuzz -t ws://localhost:64999 --scenario ./scenarios/orders.json --scenario-reuse-connection

# HTTP-to-WebSocket harness — bridge for SQLMap, ffuf, Burp, nuclei
wsfuzz -t ws://localhost:64999/api --harness
# Then: sqlmap -u "http://127.0.0.1:8765" --data='{"id": "1"}' --batch
# Or:   ffuf -u http://127.0.0.1:8765 -d 'FUZZ' -w wordlist.txt

# Harness with template — inject into a specific JSON field
wsfuzz -t ws://localhost:64999/api --harness --harness-template '{"user": "[FUZZ]"}'

# JSON-safe harness template — escapes quotes/newlines/backslashes after substitution
wsfuzz -t ws://localhost:64999/api --harness --harness-template '{"user": "[FUZZ]"}' --harness-template-format json

# Template markers can also pull from the incoming HTTP request
wsfuzz -t ws://localhost:64999/api --harness --harness-template '{"user":"[FUZZ]","tenant":"[QUERY:tenant]","token":"[HEADER:X-Token]"}'

# Additional markers: [METHOD], [PATH], [HEADERS:Name], [QUERIES:name]
# In binary harness mode, a raw "[FUZZ]" template preserves exact bytes.
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --target` | WebSocket URL | required |
| `-m, --mode` | `binary` or `text` | `binary` (`text` with `--scenario`) |
| `-n, --iterations` | Number of iterations (0 = infinite) | `0` |
| `-c, --concurrency` | Concurrent connections | `1` |
| `-s, --seeds` | Seed corpus directory | `./seeds` |
| `--max-size` | Max payload size in bytes | `200` |
| `--timeout` | Connection timeout in seconds | `5.0` |
| `--log-dir` | Crash log directory | `./crashes` |
| `--raw` | Fuzz WebSocket frame headers over raw TCP (`ws://` or `wss://`) | off |
| `--fuzz-handshake` | Fuzz WS upgrade headers in raw mode only; requires `--raw` | off |
| `-H, --header` | Custom header `K:V` (repeatable) | none |
| `--origin` | Origin header for CSWSH testing | none |
| `--tls-ca` | Custom CA bundle for `wss://` connections | none |
| `--insecure` | Disable TLS certificate verification for `wss://` | off |
| `--replay` | Replay crash `.bin` files against target | off |
| `--scenario` | JSON scenario for multi-step stateful sessions | none |
| `--scenario-fuzz-mode` | `first` or `round-robin` fuzz-step selection | `round-robin` |
| `--scenario-reuse-connection` | Reuse one WS connection across scenario iterations | off |
| `--scenario-session-history-limit` | Max prior reused-session fuzz messages saved for replay | `100` |
| `--radamsa` | Path to radamsa binary | `radamsa` |
| `-v, --verbose` | Verbose debug output | off |
| `-q, --quiet` | Quiet output (warnings/errors only) | off |
| `--no-dedupe` | Save every interesting crash instead of deduplicating by behavior | off |
| `--harness` | Run the HTTP-to-WebSocket bridge for HTTP security tools | off |
| `--harness-port` | Harness listen port | `8765` |
| `--harness-template` | Message template using `[FUZZ]` and request-derived markers | none |
| `--harness-template-format` | `raw` replacement or `json` safe rendering | `raw` |

## What it tests

**Protocol level** (raw mode):
- Reserved opcodes, unmasked frames, RSV bit abuse
- Oversized/fragmented control frames
- Payload length mismatch (declared vs actual — targets buffer pre-allocation bugs)
- Handshake header injection (version, extensions, subprotocol)
- Invalid UTF-8, malformed close codes

**Application level**:
- Mutation-based payload fuzzing via Radamsa
- Scenario-driven stateful sessions with setup, per-step expectations, JSON/regex capture, optional HTTP pre-auth, and optional connection reuse
- Crash detection via close codes >= 1002, connection resets, unhandled exceptions
- Connection state classification: connection refused (including dual-stack IPv4+IPv6), resets, and timeouts are correctly identified and filtered — only genuine crashes are logged
- Corpus feedback: crash payloads are added back to the seed pool
- CSWSH: Origin header validation testing
- Optional custom CA / insecure TLS handling for `wss://` testing in both normal and raw mode
- Harness templating from HTTP body, method, path, headers, and query parameters
- Harness support for both `Content-Length` and chunked request bodies, with oversized body rejection

## Crash Logging

Crash artifacts may include:
- `crash_<iter>_<ts>.bin` — raw payload or raw frame bytes
- `crash_<iter>_<ts>.txt` — metadata (error type, radamsa seed, duration, and any handshake-fuzz or scenario parameters)
- `crash_<iter>_<ts>.scenario.json` — saved scenario snapshot for scenario-mode crashes
- `crash_<iter>_<ts>.scenario-session.json` — capped prior-message transcript for reused-session scenario crashes
- `crash_index.json` — behavior fingerprints and duplicate counts

Crash logging deduplicates by observed behavior by default, so repeated crashes with the same transport mode, message mode, error type, close code, response hash, and fuzz context increment `crash_index.json` instead of writing more identical artifacts. Use `--no-dedupe` when every matching payload should be saved.

Replay uses the `.bin` file plus sidecar metadata when present. Raw crash artifacts record their transport mode automatically, and scenario crashes also save a `.scenario.json` snapshot. Reused-session scenario crashes save a capped `.scenario-session.json` transcript of prior fuzzed messages, so replay uses the original scenario definition and recent session history even if the working copy changes later. Replay output compares observed behavior with saved metadata and reports each artifact as `reproduced`, `changed`, or `unchecked`.

## Scenarios

Scenarios are JSON files with optional `pre_http`, `connect`, `setup`, `steps`, and `teardown` sections. `steps` must contain at least one `fuzz` step.

```json
{
  "pre_http": {
    "method": "POST",
    "url": "http://127.0.0.1:8080/login",
    "body": {"user": "test", "pass": "test"},
    "capture": {"json": {"token": "token"}}
  },
  "connect": {
    "path": "/ws/orders",
    "headers": {"Authorization": "Bearer ${token}"}
  },
  "setup": [
    {"send": {"op": "login", "user": "test", "pass": "test"}},
    {"expect": {"json": {"ok": true}}},
    {"send": {"op": "subscribe", "topic": "orders"}},
    {"expect": {"contains": "subscribed"}},
    {"capture": {"json": {"session_id": "session"}}}
  ],
  "steps": [
    {
      "fuzz": {
        "name": "update-id",
        "template": {"op": "update", "session": "${session_id}", "id": "[FUZZ]"}
      }
    },
    {"expect": {"json": {"ok": true}}}
  ]
}
```

Supported step types:
- `send`
- `fuzz`
- `expect` with `contains`, `equals`, `regex`, or `json`
- `capture` with `json` or `regex`
- `sleep`

Notes:
- Scenario mode defaults to `text` because most scenario templates are JSON/text workflows.
- Scenario fuzz control objects use `name` and `template` or `template` and `fallback`; plain application payloads such as `{"template": "[FUZZ]"}` are sent as-is.
- In binary scenario mode, raw `"[FUZZ]"` messages are supported. Embedding arbitrary binary fuzz bytes inside text/JSON templates is rejected instead of silently rewriting them.
- Reused-session replay transcripts are capped by `--scenario-session-history-limit` to keep artifact size and replay cost bounded.

Harness notes:
- In binary harness mode, raw `"[FUZZ]"` templates preserve exact bytes.
- Embedding arbitrary binary fuzz bytes inside text harness templates is rejected instead of being rewritten.
- Use `--harness-template-format json` when the template itself is JSON and marker values should be JSON-escaped after substitution.

## Tests

```bash
uv run pytest
```

415 tests covering transport, mutation, crash logging, crash deduplication, atomic crash index writes, protocol violations (RFC 6455), CSWSH, payload length mismatch, handshake fuzzing, strict raw handshake validation, connection state parity (normal vs raw mode), shared TLS configuration and config-error filtering, header/URI validation hardening, raw TLS transport, deterministic handshake-fuzz replay, scenario-based stateful sessions, strict scenario numeric validation, optional HTTP pre-auth, connection reuse, capped reused-session replay transcripts, harness HTTP parsing, oversized harness request handling, strict transfer-encoding handling, byte-faithful binary templating, JSON-safe harness templating, replay behavior reports, corrupt metadata handling, chunked requests, bounded async subprocess cleanup, early programmatic config validation, and application-level vulnerabilities.
