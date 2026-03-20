# wsfuzz

Mutation-based WebSocket fuzzer. Uses [Radamsa](https://gitlab.com/akihe/radamsa) for input generation, async I/O for concurrency, and raw TCP for protocol-level frame fuzzing.

## Requirements

- Python 3.14+
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

# Authenticated fuzzing with custom headers
wsfuzz -t ws://localhost:64999 -H "Cookie: session=abc" -H "Authorization: Bearer tok"

# CSWSH detection — test if server validates Origin
wsfuzz -t ws://localhost:64999 --origin http://evil.example.com

# Replay crashes for reproduction
wsfuzz -t ws://localhost:64999 --replay ./crashes
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
| `--raw` | Fuzz WebSocket frame headers over raw TCP | off |
| `--fuzz-handshake` | Fuzz WS upgrade headers (raw mode) | off |
| `-H, --header` | Custom header `K:V` (repeatable) | none |
| `--origin` | Origin header for CSWSH testing | none |
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
- Corpus feedback: crash payloads are added back to the seed pool
- CSWSH: Origin header validation testing

## Crash Logging

Crashes are saved as pairs:
- `crash_<iter>_<ts>.bin` — raw payload (replayable with `--replay`)
- `crash_<iter>_<ts>.txt` — metadata (error type, radamsa seed, duration)

The radamsa seed in the metadata file allows deterministic reproduction.

## Tests

```bash
uv run pytest
```

122 tests covering transport, mutation, crash logging, protocol violations (RFC 6455), CSWSH, payload length mismatch, handshake fuzzing, and application-level vulnerabilities.
