import argparse
from pathlib import Path

from wsfuzz.fuzzer import FuzzConfig, run


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
        default="binary",
        help="payload mode",
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
        "-H",
        "--header",
        action="append",
        metavar="K:V",
        help="custom header (repeatable)",
    )
    parser.add_argument("--origin", help="Origin header for CSWSH testing")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose output")

    args = parser.parse_args()

    replay_files: list[Path] = []
    if args.replay:
        for f in args.replay:
            p = Path(f)
            if p.is_file():
                replay_files.append(p)
            elif p.is_dir():
                replay_files.extend(sorted(p.glob("crash_*.bin")))

    headers: dict[str, str] = {}
    if args.header:
        for h in args.header:
            key, _, value = h.partition(":")
            if key and value:
                headers[key.strip()] = value.strip()

    config = FuzzConfig(
        target=args.target,
        mode=args.mode,
        seeds_dir=Path(args.seeds),
        iterations=args.iterations,
        max_size=args.max_size,
        timeout=args.timeout,
        log_dir=Path(args.log_dir),
        radamsa_path=args.radamsa,
        verbose=args.verbose,
        concurrency=max(1, args.concurrency),
        raw=args.raw,
        replay=replay_files,
        headers=headers,
        origin=args.origin,
        fuzz_handshake=args.fuzz_handshake,
    )

    try:
        run(config)
    except KeyboardInterrupt:
        print("\ninterrupted")
