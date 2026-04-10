import asyncio
import contextlib
import os
import subprocess
from pathlib import Path


def _radamsa_cmd(radamsa_path: str, seed_num: int | None) -> list[str]:
    cmd: list[str] = [radamsa_path]
    if seed_num is not None:
        cmd.extend(["-s", str(seed_num)])
    return cmd


def _fallback_mutation(seed_data: bytes) -> bytes:
    return os.urandom(len(seed_data) or 200)


def mutate(
    seed_data: bytes, radamsa_path: str = "radamsa", seed_num: int | None = None
) -> bytes:
    """Mutate seed data using radamsa (synchronous, for tests)."""
    try:
        result = subprocess.run(
            _radamsa_cmd(radamsa_path, seed_num),
            input=seed_data,
            capture_output=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout:
            return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return _fallback_mutation(seed_data)


async def mutate_async(
    seed_data: bytes, radamsa_path: str = "radamsa", seed_num: int | None = None
) -> bytes:
    """Mutate seed data using radamsa (async, for the fuzzer loop)."""
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *_radamsa_cmd(radamsa_path, seed_num),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(seed_data), timeout=10)
        if proc.returncode == 0 and stdout:
            return stdout
    except TimeoutError:
        if proc is not None:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            with contextlib.suppress(ProcessLookupError):
                await proc.wait()
    except (FileNotFoundError, OSError):
        pass

    return _fallback_mutation(seed_data)


def load_seeds(seeds_dir: Path) -> list[bytes]:
    seeds: list[bytes] = []
    if seeds_dir.is_dir():
        for f in sorted(seeds_dir.iterdir()):
            if f.is_file():
                data = f.read_bytes()
                if data:
                    seeds.append(data)

    if not seeds:
        seeds.append(os.urandom(200))

    return seeds
