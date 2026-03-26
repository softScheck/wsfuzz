import asyncio
import random
import time
from dataclasses import dataclass, field
from pathlib import Path

from wsfuzz.logger import CrashLogger
from wsfuzz.mutator import load_seeds, mutate_async
from wsfuzz.raw import OP_BINARY, OP_TEXT, build_frame, send_raw
from wsfuzz.transport import ConnectOpts, send_payload


@dataclass
class FuzzConfig:
    target: str
    mode: str = "binary"
    seeds_dir: Path = Path("./seeds")
    iterations: int = 0
    max_size: int = 200
    timeout: float = 5.0
    log_dir: Path = Path("./crashes")
    radamsa_path: str = "radamsa"
    verbose: bool = False
    concurrency: int = 1
    raw: bool = False
    replay: list[Path] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    origin: str | None = None
    fuzz_handshake: bool = False
    max_retries: int = 5


def run(config: FuzzConfig) -> None:
    asyncio.run(_fuzz_loop(config))


def _opts(config: FuzzConfig) -> ConnectOpts | None:
    if config.headers or config.origin:
        return ConnectOpts(headers=config.headers, origin=config.origin)
    return None


async def _replay(config: FuzzConfig) -> None:
    """Replay crash payloads from .bin files against the target."""
    print("wsfuzz - Replay Mode")
    print(f"target:  {config.target}")
    print(f"files:   {len(config.replay)}")
    print()

    opts = _opts(config)
    for path in config.replay:
        payload = path.read_bytes()
        if config.raw:
            result = await send_raw(config.target, payload, config.timeout, opts)
        else:
            result = await send_payload(
                config.target, payload, config.mode, config.timeout, opts
            )

        status = f"ERROR {result.error_type}: {result.error}" if result.error else "ok"
        print(f"[{path.name}] {status} ({len(payload)}b, {result.duration_ms:.0f}ms)")


async def _fuzz_loop(config: FuzzConfig) -> None:
    if config.replay:
        await _replay(config)
        return

    corpus = load_seeds(config.seeds_dir)
    logger = CrashLogger(config.log_dir)
    opts = _opts(config)

    print("wsfuzz - WebSocket Fuzzer")
    print(f"target:     {config.target}")
    print(f"mode:       {'raw' if config.raw else config.mode}")
    print(f"seeds:      {len(corpus)}")
    print(f"max_size:   {config.max_size}")
    print(f"concurrency: {config.concurrency}")
    if config.fuzz_handshake:
        print("handshake:  fuzz")
    print(f"crashes:    {config.log_dir}")
    print()

    start_time = time.monotonic()
    consecutive_refused = 0
    stop = False

    # Payload length mismatch values for testing buffer pre-allocation bugs
    length_mismatches = [0, 1, 125, 126, 65535, 65536, 2**31 - 1]

    async def _fuzz_one(iteration: int) -> None:
        nonlocal consecutive_refused, stop
        seed_index = random.randrange(len(corpus))
        seed = corpus[seed_index]
        radamsa_seed = random.randint(0, 2**32 - 1)

        payload = await mutate_async(seed, config.radamsa_path, radamsa_seed)
        if len(payload) > config.max_size:
            payload = payload[: config.max_size]

        if config.raw:
            opcode = OP_TEXT if config.mode == "text" else OP_BINARY
            # ~5% chance of payload length mismatch to test buffer pre-allocation
            fake_length = (
                random.choice(length_mismatches) if random.random() < 0.05 else None
            )
            frame = build_frame(
                payload,
                opcode=random.choice([opcode, *range(3, 8), *range(0xB, 0x10)]),
                fin=random.random() > 0.1,
                mask=random.random() > 0.1,
                rsv1=random.random() > 0.8,
                rsv2=random.random() > 0.9,
                rsv3=random.random() > 0.9,
                fake_length=fake_length,
            )
            result = await send_raw(
                config.target,
                frame,
                config.timeout,
                opts,
                fuzz_handshake=config.fuzz_handshake,
            )
        else:
            result = await send_payload(
                config.target, payload, config.mode, config.timeout, opts
            )

        if result.connection_refused:
            consecutive_refused += 1
            print(f"[!] connection refused - is the server running at {config.target}?")
            if config.max_retries > 0 and consecutive_refused >= config.max_retries:
                print(f"[!] giving up after {consecutive_refused} consecutive failures")
                stop = True
            else:
                await asyncio.sleep(1)
            return

        consecutive_refused = 0

        if logger.is_interesting(result):
            logger.log_crash(iteration, payload, result, seed_index, radamsa_seed)
            corpus.append(payload)
            msg = f"[CRASH] #{iteration} {result.error_type}: {result.error}"
            print(f"{msg} ({len(payload)}b, {result.duration_ms:.0f}ms)")
        elif config.verbose:
            print(f"[{iteration}] ok ({len(payload)}b, {result.duration_ms:.0f}ms)")

    iteration = 0
    try:
        if config.concurrency <= 1:
            while not stop and (
                config.iterations == 0 or iteration < config.iterations
            ):
                await _fuzz_one(iteration)
                iteration += 1
                if iteration % 100 == 0:
                    elapsed = time.monotonic() - start_time
                    rate = iteration / elapsed if elapsed > 0 else 0
                    print(
                        f"[{iteration}] running... ({logger.crash_count} crashes, {rate:.1f} req/s)"
                    )
        else:
            while not stop and (
                config.iterations == 0 or iteration < config.iterations
            ):
                remaining = (
                    (config.iterations - iteration)
                    if config.iterations > 0
                    else config.concurrency
                )
                batch = min(config.concurrency, remaining)
                await asyncio.gather(*[_fuzz_one(iteration + j) for j in range(batch)])
                iteration += batch
                if iteration % 100 < batch:
                    elapsed = time.monotonic() - start_time
                    rate = iteration / elapsed if elapsed > 0 else 0
                    print(
                        f"[{iteration}] running... ({logger.crash_count} crashes, {rate:.1f} req/s)"
                    )
    except KeyboardInterrupt:
        pass

    elapsed = time.monotonic() - start_time
    rate = iteration / elapsed if elapsed > 0 else 0
    print(logger.summary(iteration))
    print(f"rate: {rate:.1f} req/s")
