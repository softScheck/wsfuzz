import argparse
import math
from pathlib import Path

from wsfuzz.fuzzer import FuzzConfig, run
from wsfuzz.harness import run_harness
from wsfuzz.scenario import ScenarioError, load_scenario, scenario_requires_text_mode
from wsfuzz.transport import (
    contains_control_chars,
    is_http_token,
    make_connect_opts,
    validate_ws_uri,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="wsfuzz",
        description="WebSocket fuzzer using Radamsa for input mutation",
    )
    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="WebSocket URL (e.g. ws://localhost:64999)",
    )
    parser.add_argument(
        "-m",
        "--mode",
        choices=["binary", "text"],
        help="payload mode (default: binary, or text with --scenario)",
    )
    parser.add_argument(
        "-s", "--seeds", default="./seeds", help="seed corpus directory"
    )
    parser.add_argument(
        "-n", "--iterations", type=int, default=0, help="iterations, 0 = infinite"
    )
    parser.add_argument(
        "-c", "--concurrency", type=int, default=1, help="concurrent connections"
    )
    parser.add_argument(
        "--max-size", type=int, default=200, help="max payload size in bytes"
    )
    parser.add_argument(
        "--timeout", type=float, default=5.0, help="connection/read timeout in seconds"
    )
    parser.add_argument("--log-dir", default="./crashes", help="crash log directory")
    parser.add_argument("--radamsa", default="radamsa", help="path to radamsa binary")
    parser.add_argument(
        "--raw", action="store_true", help="raw frame mode: fuzz frame headers"
    )
    parser.add_argument(
        "--fuzz-handshake",
        action="store_true",
        help="fuzz WS handshake headers (raw mode)",
    )
    parser.add_argument(
        "--replay", nargs="+", metavar="FILE", help="replay crash .bin files"
    )
    parser.add_argument(
        "--scenario",
        metavar="FILE",
        help="JSON scenario for multi-step stateful sessions",
    )
    parser.add_argument(
        "--scenario-fuzz-mode",
        choices=["first", "round-robin"],
        default="round-robin",
        help="which scenario fuzz step to target each iteration",
    )
    parser.add_argument(
        "--scenario-reuse-connection",
        action="store_true",
        help="reuse one WebSocket connection across scenario iterations",
    )
    parser.add_argument(
        "--scenario-session-history-limit",
        type=int,
        default=100,
        help="max prior reused-session fuzz messages to save for replay (0 = unlimited)",
    )
    parser.add_argument(
        "-H",
        "--header",
        action="append",
        metavar="K:V",
        help="custom header (repeatable)",
    )
    parser.add_argument("--origin", help="Origin header for CSWSH testing")
    parser.add_argument(
        "--tls-ca",
        metavar="FILE",
        help="custom CA bundle for wss:// connections",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="disable TLS certificate verification for wss:// connections",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=5,
        help="stop after N consecutive connection refused errors (0 = never stop, default: 5)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose output")
    parser.add_argument(
        "--no-dedupe",
        action="store_true",
        help="save every interesting crash instead of deduplicating by behavior",
    )
    parser.add_argument(
        "--harness",
        action="store_true",
        help="HTTP-to-WebSocket harness mode for external tools",
    )
    parser.add_argument(
        "--harness-port",
        type=int,
        default=8765,
        help="harness listen port (default: 8765)",
    )
    parser.add_argument(
        "--harness-template",
        metavar="TPL",
        help='message template with [FUZZ] marker (e.g. \'{"id": "[FUZZ]"}\')',
    )
    parser.add_argument(
        "--harness-template-format",
        choices=["raw", "json"],
        default="raw",
        help="template renderer: raw string replacement or JSON-safe rendering",
    )

    args = parser.parse_args()
    try:
        validate_ws_uri(args.target)
    except ValueError as exc:
        parser.error(str(exc))
    if args.fuzz_handshake and not args.raw:
        parser.error("--fuzz-handshake requires --raw")
    if args.scenario and args.raw:
        parser.error("--scenario is not supported with --raw")
    if args.scenario and args.harness:
        parser.error("--scenario is not supported with --harness")
    if args.harness and args.raw:
        parser.error("--raw is not supported with --harness")
    if args.harness and args.replay:
        parser.error("--replay is not supported with --harness")
    if not args.harness and args.harness_template:
        parser.error("--harness-template requires --harness")
    if not args.harness and args.harness_template_format != "raw":
        parser.error("--harness-template-format requires --harness")
    if not args.harness and args.harness_port != 8765:
        parser.error("--harness-port requires --harness")
    if (
        args.harness
        and args.harness_template_format != "raw"
        and not args.harness_template
    ):
        parser.error("--harness-template-format requires --harness-template")
    if args.scenario_reuse_connection and not args.scenario:
        parser.error("--scenario-reuse-connection requires --scenario")
    if args.iterations < 0:
        parser.error("--iterations must be non-negative")
    if args.max_size <= 0:
        parser.error("--max-size must be positive")
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.concurrency < 1:
        parser.error("--concurrency must be positive")
    if args.max_retries < 0:
        parser.error("--max-retries must be non-negative")
    if args.scenario_session_history_limit < 0:
        parser.error("--scenario-session-history-limit must be non-negative")
    if not 1 <= args.harness_port <= 65535:
        parser.error("--harness-port must be between 1 and 65535")
    if args.scenario_reuse_connection and args.concurrency > 1:
        parser.error("--scenario-reuse-connection requires concurrency 1")
    if args.origin and any(char in args.origin for char in "\r\n"):
        parser.error("--origin must not contain newlines")
    if args.origin and contains_control_chars(args.origin):
        parser.error("--origin must not contain control characters")

    selected_mode = args.mode or ("text" if args.scenario else "binary")
    if args.scenario and args.mode == "binary":
        try:
            scenario = load_scenario(Path(args.scenario))
        except ScenarioError as exc:
            parser.error(str(exc))
        if scenario_requires_text_mode(scenario):
            parser.error(
                "binary scenario mode only supports raw [FUZZ] messages or binary-safe setup steps; "
                "use -m text for structured JSON/text scenarios"
            )

    replay_files: list[Path] = []
    if args.replay:
        for f in args.replay:
            p = Path(f)
            if p.is_file():
                if p.suffix != ".bin":
                    parser.error("--replay files must be crash .bin artifacts")
                replay_files.append(p)
            elif p.is_dir():
                replay_files.extend(sorted(p.glob("crash_*.bin")))
        if not replay_files:
            parser.error("--replay did not match any crash .bin files")

    headers: dict[str, str] = {}
    if args.header:
        for h in args.header:
            raw_key, sep, raw_value = h.partition(":")
            if any(char in raw_key + raw_value for char in "\r\n"):
                parser.error("--header must not contain newlines")
            key = raw_key.strip()
            value = raw_value.strip()
            if not sep or not key:
                parser.error("--header must use K:V format")
            if raw_key != key or not is_http_token(key):
                parser.error("--header name must be a valid HTTP token")
            if contains_control_chars(value):
                parser.error("--header must not contain control characters")
            headers[key] = value

    config = FuzzConfig(
        target=args.target,
        mode=selected_mode,
        seeds_dir=Path(args.seeds),
        iterations=args.iterations,
        max_size=args.max_size,
        timeout=args.timeout,
        log_dir=Path(args.log_dir),
        radamsa_path=args.radamsa,
        verbose=args.verbose,
        concurrency=args.concurrency,
        raw=args.raw,
        replay=replay_files,
        headers=headers,
        origin=args.origin,
        ca_file=args.tls_ca,
        insecure=args.insecure,
        fuzz_handshake=args.fuzz_handshake,
        max_retries=args.max_retries,
        scenario=Path(args.scenario) if args.scenario else None,
        scenario_fuzz_mode=args.scenario_fuzz_mode,
        scenario_reuse_connection=args.scenario_reuse_connection,
        scenario_session_history_limit=args.scenario_session_history_limit,
        crash_dedup=not args.no_dedupe,
    )

    if args.harness:
        import asyncio

        harness_mode = args.mode or "text"
        try:
            opts = make_connect_opts(
                headers,
                args.origin,
                ca_file=args.tls_ca,
                insecure=args.insecure,
            )
            asyncio.run(
                run_harness(
                    args.target,
                    mode=harness_mode,
                    timeout=args.timeout,
                    opts=opts,
                    template=args.harness_template,
                    template_format=args.harness_template_format,
                    listen_port=args.harness_port,
                )
            )
        except ValueError as exc:
            parser.error(str(exc))
        except KeyboardInterrupt:
            print("\ninterrupted")
        return

    try:
        run(config)
    except (ScenarioError, ValueError) as exc:
        parser.error(str(exc))
    except KeyboardInterrupt:
        print("\ninterrupted")
