# wsfuzz

Mutation-based WebSocket fuzzer. Uses [Radamsa](https://gitlab.com/akihe/radamsa) for input generation, async I/O for concurrency, and raw TCP for protocol-level frame fuzzing. It is optimized for connect-send-observe workflows rather than long stateful WebSocket sessions.

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

# HTTP-to-WebSocket harness — bridge for SQLMap, ffuf, Burp, nuclei
wsfuzz -t ws://localhost:64999/api --harness
# Then: sqlmap -u "http://127.0.0.1:8765" --data='{"id": "1"}' --batch
# Or:   ffuf -u http://127.0.0.1:8765 -d 'FUZZ' -w wordlist.txt

# Harness with template — inject into a specific JSON field
wsfuzz -t ws://localhost:64999/api --harness --harness-template '{"user": "[FUZZ]"}'

# Template markers can also pull from the incoming HTTP request
wsfuzz -t ws://localhost:64999/api --harness --harness-template '{"user":"[FUZZ]","tenant":"[QUERY:tenant]","token":"[HEADER:X-Token]"}'

# Additional markers: [METHOD], [PATH], [HEADERS:Name], [QUERIES:name]
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --target` | WebSocket URL | required |
| `-m, --mode` | `binary` or `text` | `binary` |
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
| `--radamsa` | Path to radamsa binary | `radamsa` |
| `-v, --verbose` | Verbose output | off |

## What it tests

**Protocol level** (raw mode):
- Reserved opcodes, unmasked frames, RSV bit abuse
- Oversized/fragmented control frames
- Payload length mismatch (declared vs actual — targets buffer pre-allocation bugs)
- Handshake header injection (version, extensions, subprotocol)
- Invalid UTF-8, malformed close codes

**Application level**:
- Mutation-based payload fuzzing via Radamsa
- Crash detection via close codes >= 1002, connection resets, unhandled exceptions
- Connection state classification: connection refused (including dual-stack IPv4+IPv6), resets, and timeouts are correctly identified and filtered — only genuine crashes are logged
- Corpus feedback: crash payloads are added back to the seed pool
- CSWSH: Origin header validation testing
- Optional custom CA / insecure TLS handling for `wss://` testing in both normal and raw mode
- Harness templating from HTTP body, method, path, headers, and query parameters
- Harness support for both `Content-Length` and chunked request bodies

## Crash Logging

Crashes are saved as pairs:
- `crash_<iter>_<ts>.bin` — raw payload or raw frame bytes
- `crash_<iter>_<ts>.txt` — metadata (error type, radamsa seed, duration, and any handshake-fuzz parameters)

Replay uses the `.bin` file plus the sidecar `.txt` metadata when present. The radamsa seed and saved handshake-fuzz parameters allow deterministic reproduction.

## Tests

```bash
uv run pytest
```

190 tests covering transport, mutation, crash logging, protocol violations (RFC 6455), CSWSH, payload length mismatch, handshake fuzzing, strict raw handshake validation, connection state parity (normal vs raw mode), shared TLS configuration, raw TLS transport, deterministic handshake-fuzz replay, harness HTTP parsing, chunked requests, async subprocess cleanup, and application-level vulnerabilities.
