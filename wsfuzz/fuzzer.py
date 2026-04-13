import asyncio
import base64
import binascii
import hashlib
import json
import math
import random
import shutil
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from wsfuzz.logger import CrashLogger
from wsfuzz.mutator import load_seeds, mutate_async
from wsfuzz.raw import (
    OP_BINARY,
    OP_TEXT,
    HandshakeFuzz,
    build_frame,
    make_handshake_fuzz,
    send_raw,
)
from wsfuzz.scenario import (
    FuzzStep,
    Scenario,
    ScenarioSession,
    load_scenario,
    run_scenario_iteration,
    scenario_metadata,
    scenario_requires_text_mode,
    select_fuzz_step,
)
from wsfuzz.transport import (
    TransportResult,
    make_connect_opts,
    send_payload,
    validate_ws_uri,
)


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
    ca_file: str | None = None
    insecure: bool = False
    fuzz_handshake: bool = False
    max_retries: int = 5
    scenario: Path | None = None
    scenario_fuzz_mode: str = "round-robin"
    scenario_reuse_connection: bool = False
    scenario_session_history_limit: int = 100
    crash_dedup: bool = True


@dataclass(frozen=True)
class ReplayComparison:
    status: str
    detail: str


def run(config: FuzzConfig) -> None:
    validate_ws_uri(config.target)
    if config.mode not in {"text", "binary"}:
        raise ValueError("mode must be 'text' or 'binary'")
    if config.iterations < 0:
        raise ValueError("iterations must be non-negative")
    if config.max_size <= 0:
        raise ValueError("max_size must be positive")
    if not math.isfinite(config.timeout) or config.timeout <= 0:
        raise ValueError("timeout must be positive")
    if config.concurrency < 1:
        raise ValueError("concurrency must be positive")
    if config.max_retries < 0:
        raise ValueError("max_retries must be non-negative")
    if config.scenario_session_history_limit < 0:
        raise ValueError("scenario_session_history_limit must be non-negative")
    if config.fuzz_handshake and not config.raw:
        raise ValueError("--fuzz-handshake requires raw mode")
    if config.raw and config.scenario is not None:
        raise ValueError("--scenario is not supported with raw mode")
    if config.scenario_reuse_connection and config.scenario is None:
        raise ValueError("--scenario-reuse-connection requires scenario")
    if config.scenario_reuse_connection and config.concurrency > 1:
        raise ValueError("--scenario-reuse-connection requires concurrency 1")
    if config.scenario_fuzz_mode not in {"first", "round-robin"}:
        raise ValueError("scenario_fuzz_mode must be 'first' or 'round-robin'")
    make_connect_opts(
        config.headers,
        config.origin,
        ca_file=config.ca_file,
        insecure=config.insecure,
    )
    _validate_replay_files(config.replay)
    if not config.replay and config.scenario is not None:
        _validate_scenario_config(config)
    asyncio.run(_fuzz_loop(config))


def _validate_replay_files(replay: list[Path]) -> None:
    for path in replay:
        if path.suffix != ".bin":
            raise ValueError("replay files must be crash .bin artifacts")
        if not path.is_file():
            raise ValueError(f"replay file does not exist: {path}")


def _validate_scenario_config(config: FuzzConfig) -> None:
    assert config.scenario is not None
    scenario = load_scenario(config.scenario)
    if config.mode == "binary" and scenario_requires_text_mode(scenario):
        raise ValueError(
            "binary scenario mode only supports raw [FUZZ] messages or binary-safe setup steps; "
            "use -m text for structured JSON/text scenarios"
        )


def _load_metadata(path: Path) -> dict[str, str]:
    metadata_path = path.with_suffix(".txt")
    if not metadata_path.is_file():
        return {}
    metadata: dict[str, str] = {}
    try:
        lines = metadata_path.read_text().splitlines()
    except (OSError, UnicodeDecodeError):
        return metadata
    for line in lines:
        key, sep, value = line.partition(":")
        if sep:
            metadata[key.strip()] = value.lstrip()
    return metadata


def _load_handshake_fuzz(metadata: dict[str, str]) -> HandshakeFuzz | None:
    if metadata.get("handshake_fuzz") != "true":
        return None
    return HandshakeFuzz(
        version=metadata.get("handshake_version", "13"),
        extension=metadata.get("handshake_extension") or None,
        protocol=metadata.get("handshake_protocol") or None,
    )


def _load_transport_mode(metadata: dict[str, str]) -> str | None:
    transport_mode = metadata.get("transport_mode")
    if transport_mode in {"normal", "raw", "scenario"}:
        return transport_mode
    return None


def _load_scenario_metadata(
    metadata: dict[str, str],
    path: Path,
) -> tuple[Path | None, int | None]:
    scenario_path = metadata.get("scenario_path")
    fuzz_ordinal = metadata.get("scenario_fuzz_ordinal")
    return (
        Path(scenario_path) if scenario_path else None,
        _parse_non_negative_int(fuzz_ordinal, "scenario_fuzz_ordinal", path)
        if fuzz_ordinal is not None
        else None,
    )


def _load_mode_field(metadata: dict[str, str], key: str) -> str | None:
    value = metadata.get(key)
    if value in {"text", "binary"}:
        return value
    return None


def _metadata_value(metadata: dict[str, str], key: str) -> str | None:
    value = metadata.get(key)
    if value is None or value in {"", "None"}:
        return None
    return value


def _compare_replay(
    metadata: dict[str, str],
    result: TransportResult,
) -> ReplayComparison:
    expected_error_type = _metadata_value(metadata, "error_type")
    expected_close_code = _metadata_value(metadata, "close_code")
    expected_response_sha256 = _metadata_value(metadata, "response_sha256")
    has_error_type = "error_type" in metadata
    has_close_code = "close_code" in metadata
    has_response_sha256 = "response_sha256" in metadata
    if not has_error_type and not has_close_code and not has_response_sha256:
        return ReplayComparison("unchecked", "no baseline metadata")

    mismatches: list[str] = []
    if has_error_type and expected_error_type != result.error_type:
        mismatches.append(
            f"error_type expected {expected_error_type}, got {result.error_type}"
        )
    if has_close_code and expected_close_code != (
        str(result.close_code) if result.close_code is not None else None
    ):
        mismatches.append(
            f"close_code expected {expected_close_code}, got {result.close_code}"
        )
    if has_response_sha256:
        actual_response_sha256 = (
            hashlib.sha256(result.response).hexdigest()
            if result.response is not None
            else None
        )
        if expected_response_sha256 != actual_response_sha256:
            mismatches.append("response_sha256 changed")

    if mismatches:
        return ReplayComparison("changed", "; ".join(mismatches))
    return ReplayComparison("reproduced", "observed behavior matches metadata")


def _resolve_replay_scenario_path(
    crash_file: Path,
    configured_path: Path | None,
    metadata: dict[str, str],
) -> Path | None:
    snapshot_path = crash_file.with_suffix(".scenario.json")
    if snapshot_path.is_file():
        return snapshot_path
    scenario_path, _ = _load_scenario_metadata(metadata, crash_file)
    if scenario_path is not None:
        if scenario_path.is_absolute():
            return scenario_path
        return (crash_file.parent / scenario_path).resolve()
    if configured_path is not None:
        return configured_path.resolve()
    return None


def _load_scenario_session_history(path: Path) -> list[tuple[int, bytes]]:
    session_path = path.with_suffix(".scenario-session.json")
    if not session_path.is_file():
        return []
    try:
        session_text = session_path.read_text()
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(
            f"scenario session history cannot be read: {session_path}"
        ) from exc
    try:
        raw = json.loads(session_text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"invalid scenario session history JSON: {session_path}"
        ) from exc
    if not isinstance(raw, dict):
        raise ValueError(f"scenario session history must be an object: {session_path}")
    entries = raw.get("entries", [])
    if not isinstance(entries, list):
        raise ValueError(
            f"scenario session history entries must be a list: {session_path}"
        )
    history: list[tuple[int, bytes]] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(
                f"scenario session history entry {index} must be an object: {session_path}"
            )
        entry = cast(dict[str, Any], entry)
        payload_b64 = entry.get("payload_b64")
        fuzz_ordinal = entry.get("fuzz_ordinal")
        if fuzz_ordinal is None:
            raise ValueError(
                f"scenario session history entry {index} missing fuzz_ordinal: {session_path}"
            )
        if not isinstance(payload_b64, str):
            raise ValueError(
                f"scenario session history entry {index} payload_b64 must be a string: {session_path}"
            )
        ordinal = _parse_non_negative_int(
            fuzz_ordinal,
            f"scenario session history entry {index} fuzz_ordinal",
            session_path,
        )
        try:
            payload = base64.b64decode(payload_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError(
                f"scenario session history entry {index} payload_b64 is invalid: {session_path}"
            ) from exc
        history.append((ordinal, payload))
    return history


def _parse_non_negative_int(value: object, name: str, source: Path) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"{name} must be an integer in {source}")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer in {source}") from exc
    if parsed < 0:
        raise ValueError(f"{name} must be non-negative in {source}")
    return parsed


def _scenario_fuzz_step_by_ordinal(
    scenario: Scenario,
    ordinal: int,
    source: Path,
) -> FuzzStep:
    try:
        return scenario.fuzz_steps[ordinal]
    except IndexError as exc:
        raise ValueError(
            f"scenario_fuzz_ordinal {ordinal} is out of range for {source}"
        ) from exc


def _dump_scenario_session_history(history: list[tuple[int, bytes]]) -> str:
    return json.dumps(
        {
            "entries": [
                {
                    "fuzz_ordinal": fuzz_ordinal,
                    "payload_b64": base64.b64encode(payload).decode(),
                }
                for fuzz_ordinal, payload in history
            ]
        }
    )


def _scenario_artifacts(
    scenario: Scenario | None,
    scenario_session: ScenarioSession | None,
    prior_session_history: list[tuple[int, bytes]],
) -> dict[str, str] | None:
    if scenario is None:
        return None
    artifacts: dict[str, str] = {".scenario.json": scenario.raw_text}
    if scenario_session is not None and prior_session_history:
        artifacts[".scenario-session.json"] = _dump_scenario_session_history(
            prior_session_history
        )
    return artifacts


async def _replay(config: FuzzConfig) -> None:
    """Replay crash payloads from .bin files against the target."""
    print("wsfuzz - Replay Mode")
    print(f"target:  {config.target}")
    print(f"files:   {len(config.replay)}")
    print()

    opts = make_connect_opts(
        config.headers,
        config.origin,
        ca_file=config.ca_file,
        insecure=config.insecure,
    )
    replay_counts = Counter[str]()
    for path in config.replay:
        payload = path.read_bytes()
        metadata = _load_metadata(path)
        replay_transport_mode = _load_transport_mode(metadata)
        if replay_transport_mode is not None:
            replay_kind = replay_transport_mode
        elif config.raw:
            replay_kind = "raw"
        elif (
            config.scenario is not None
            or _resolve_replay_scenario_path(path, None, metadata) is not None
        ):
            replay_kind = "scenario"
        else:
            replay_kind = "normal"

        if replay_kind == "raw":
            handshake_fuzz = _load_handshake_fuzz(metadata)
            result = await send_raw(
                config.target,
                payload,
                config.timeout,
                opts,
                handshake_fuzz=handshake_fuzz,
            )
        elif replay_kind == "scenario":
            _, fuzz_ordinal = _load_scenario_metadata(metadata, path)
            scenario_source = _resolve_replay_scenario_path(
                path,
                config.scenario,
                metadata,
            )
            if scenario_source is None:
                raise ValueError("scenario replay metadata is missing scenario_path")
            loaded_scenario = load_scenario(scenario_source)
            scenario_mode = (
                _load_mode_field(metadata, "scenario_mode")
                or _load_mode_field(metadata, "message_mode")
                or config.mode
            )
            fuzz_step = (
                _scenario_fuzz_step_by_ordinal(
                    loaded_scenario,
                    fuzz_ordinal,
                    path,
                )
                if fuzz_ordinal is not None
                else select_fuzz_step(loaded_scenario, 0, config.scenario_fuzz_mode)
            )
            session_history = _load_scenario_session_history(path)
            if session_history:
                session = ScenarioSession(
                    loaded_scenario,
                    config.target,
                    scenario_mode,
                    config.timeout,
                    opts,
                )
                try:
                    result = None
                    for prior_ordinal, prior_payload in session_history:
                        prior_step = _scenario_fuzz_step_by_ordinal(
                            loaded_scenario,
                            prior_ordinal,
                            path.with_suffix(".scenario-session.json"),
                        )
                        result = await session.run(prior_payload, prior_step)
                        if result.error is not None or result.close_code is not None:
                            break
                    else:
                        result = await session.run(payload, fuzz_step)
                finally:
                    await session.close()
                assert result is not None
            else:
                result = await run_scenario_iteration(
                    loaded_scenario,
                    config.target,
                    payload,
                    scenario_mode,
                    config.timeout,
                    opts,
                    fuzz_step,
                )
        else:
            replay_mode = _load_mode_field(metadata, "message_mode") or config.mode
            result = await send_payload(
                config.target, payload, replay_mode, config.timeout, opts
            )

        status = f"ERROR {result.error_type}: {result.error}" if result.error else "ok"
        comparison = _compare_replay(metadata, result)
        replay_counts[comparison.status] += 1
        print(
            f"[{path.name}] {status} ({len(payload)}b, {result.duration_ms:.0f}ms) "
            f"replay: {comparison.status} ({comparison.detail})"
        )
    if config.replay:
        print(
            "replay summary: "
            f"{replay_counts['reproduced']} reproduced, "
            f"{replay_counts['changed']} changed, "
            f"{replay_counts['unchecked']} unchecked"
        )


async def _fuzz_loop(config: FuzzConfig) -> None:
    if config.replay:
        await _replay(config)
        return

    scenario = load_scenario(config.scenario) if config.scenario else None
    corpus = load_seeds(config.seeds_dir)
    logger = CrashLogger(config.log_dir, dedupe=config.crash_dedup)
    opts = make_connect_opts(
        config.headers,
        config.origin,
        ca_file=config.ca_file,
        insecure=config.insecure,
    )

    print("wsfuzz - WebSocket Fuzzer")
    print(f"target:     {config.target}")
    print(f"mode:       {'raw' if config.raw else config.mode}")
    print(f"seeds:      {len(corpus)}")
    print(f"max_size:   {config.max_size}")
    print(f"concurrency: {config.concurrency}")
    if scenario is not None:
        print(f"scenario:   {scenario.path}")
        print(f"scenario-fuzz: {config.scenario_fuzz_mode}")
        if config.scenario_reuse_connection:
            print("scenario-session: reused")
    print(f"dedupe:     {'on' if config.crash_dedup else 'off'}")
    if config.fuzz_handshake:
        print("handshake:  fuzz")
    print(f"crashes:    {config.log_dir}")
    if not shutil.which(config.radamsa_path):
        print(
            "[!] radamsa not found — using random mutation (install: https://gitlab.com/akihe/radamsa)"
        )
    print()

    start_time = time.monotonic()
    consecutive_refused = 0
    stop = False
    scenario_session_history: list[tuple[int, bytes]] = []
    scenario_session_history_seen = 0
    scenario_session = (
        ScenarioSession(
            scenario,
            config.target,
            config.mode,
            config.timeout,
            opts,
        )
        if scenario is not None and config.scenario_reuse_connection
        else None
    )

    # Payload length mismatch values for testing buffer pre-allocation bugs
    length_mismatches = [0, 1, 125, 126, 65535, 65536, 2**31 - 1]
    # Reserved + valid opcodes for raw-mode fuzzing
    raw_opcode = OP_TEXT if config.mode == "text" else OP_BINARY
    raw_opcodes = [raw_opcode, *range(3, 8), *range(0xB, 0x10)]

    async def _fuzz_one(iteration: int) -> None:
        nonlocal consecutive_refused, stop, scenario_session_history_seen
        seed_index = random.randrange(len(corpus))
        seed = corpus[seed_index]
        radamsa_seed = random.randint(0, 2**32 - 1)

        payload = await mutate_async(seed, config.radamsa_path, radamsa_seed)
        if len(payload) > config.max_size:
            payload = payload[: config.max_size]

        sent_payload = payload
        handshake_fuzz: HandshakeFuzz | None = None
        selected_fuzz_step = (
            select_fuzz_step(scenario, iteration, config.scenario_fuzz_mode)
            if scenario is not None
            else None
        )
        if config.raw:
            # ~5% chance of payload length mismatch to test buffer pre-allocation
            fake_length = (
                random.choice(length_mismatches) if random.random() < 0.05 else None
            )
            handshake_fuzz = make_handshake_fuzz(enabled=config.fuzz_handshake)
            frame = build_frame(
                payload,
                opcode=random.choice(raw_opcodes),
                fin=random.random() > 0.1,
                mask=random.random() > 0.1,
                rsv1=random.random() > 0.8,
                rsv2=random.random() > 0.9,
                rsv3=random.random() > 0.9,
                fake_length=fake_length,
            )
            # Persist the exact frame bytes so raw-mode crash files are replayable.
            sent_payload = frame
            result = await send_raw(
                config.target,
                frame,
                config.timeout,
                opts,
                handshake_fuzz=handshake_fuzz,
            )
        elif scenario is not None:
            assert selected_fuzz_step is not None
            if scenario_session is not None:
                result = await scenario_session.run(payload, selected_fuzz_step)
            else:
                result = await run_scenario_iteration(
                    scenario,
                    config.target,
                    payload,
                    config.mode,
                    config.timeout,
                    opts,
                    selected_fuzz_step,
                )
        else:
            result = await send_payload(
                config.target, payload, config.mode, config.timeout, opts
            )

        if result.connection_refused:
            if scenario_session is not None:
                scenario_session_history.clear()
                scenario_session_history_seen = 0
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
            prior_session_history = list(scenario_session_history)
            prior_session_history_seen = scenario_session_history_seen
            extra_metadata: dict[str, str] = {
                "transport_mode": "raw"
                if config.raw
                else "scenario"
                if scenario
                else "normal",
                "message_mode": config.mode,
            }
            if handshake_fuzz is not None:
                extra_metadata.update(
                    handshake_fuzz="true",
                    handshake_version=handshake_fuzz.version,
                    handshake_extension=handshake_fuzz.extension or "",
                    handshake_protocol=handshake_fuzz.protocol or "",
                )
            if scenario is not None and selected_fuzz_step is not None:
                extra_metadata.update(scenario_metadata(scenario, selected_fuzz_step))
                extra_metadata["scenario_mode"] = config.mode
                if scenario_session is not None:
                    extra_metadata["scenario_session_history_limit"] = str(
                        config.scenario_session_history_limit
                    )
                    extra_metadata["scenario_session_history_saved"] = str(
                        len(prior_session_history)
                    )
                    extra_metadata["scenario_session_history_truncated"] = (
                        "true"
                        if prior_session_history_seen > len(prior_session_history)
                        else "false"
                    )
            crash_log = logger.log_crash(
                iteration,
                sent_payload,
                result,
                seed_index,
                radamsa_seed,
                extra_metadata=extra_metadata,
                extra_artifacts=_scenario_artifacts(
                    scenario, scenario_session, prior_session_history
                ),
            )
            if crash_log.saved:
                corpus.append(payload)
                msg = f"[CRASH] #{iteration} {result.error_type}: {result.error}"
                print(f"{msg} ({len(sent_payload)}b, {result.duration_ms:.0f}ms)")
            elif config.verbose:
                print(
                    f"[DUP] #{iteration} {result.error_type}: {result.error} "
                    f"(seen {crash_log.duplicate_count}x)"
                )
        elif config.verbose:
            print(f"[{iteration}] ok ({len(payload)}b, {result.duration_ms:.0f}ms)")

        if scenario_session is not None and selected_fuzz_step is not None:
            if result.error is None and result.close_code is None:
                scenario_session_history_seen += 1
                scenario_session_history.append((selected_fuzz_step.ordinal, payload))
                if (
                    config.scenario_session_history_limit > 0
                    and len(scenario_session_history)
                    > config.scenario_session_history_limit
                ):
                    scenario_session_history[:] = scenario_session_history[
                        -config.scenario_session_history_limit :
                    ]
            else:
                scenario_session_history.clear()
                scenario_session_history_seen = 0

    def _print_progress(iteration: int) -> None:
        elapsed = time.monotonic() - start_time
        rate = iteration / elapsed if elapsed > 0 else 0
        print(
            f"[{iteration}] running... ({logger.crash_count} crashes, {rate:.1f} req/s)"
        )

    iteration = 0
    try:
        if config.concurrency <= 1:
            while not stop and (
                config.iterations == 0 or iteration < config.iterations
            ):
                await _fuzz_one(iteration)
                iteration += 1
                if iteration % 100 == 0:
                    _print_progress(iteration)
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
                    _print_progress(iteration)
    except KeyboardInterrupt:
        pass
    finally:
        if scenario_session is not None:
            await scenario_session.close()

    elapsed = time.monotonic() - start_time
    rate = iteration / elapsed if elapsed > 0 else 0
    print(logger.summary(iteration))
    print(f"rate: {rate:.1f} req/s")
