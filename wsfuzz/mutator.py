import asyncio
import os
import subprocess
from pathlib import Path


def mutate(
    seed_data: bytes, radamsa_path: str = "radamsa", seed_num: int | None = None
) -> bytes:
    """Mutate seed data using radamsa (synchronous, for tests)."""
    cmd: list[str] = [radamsa_path]
    if seed_num is not None:
        cmd.extend(["-s", str(seed_num)])

    try:
        result = subprocess.run(cmd, input=seed_data, capture_output=True, timeout=10)
        if result.returncode == 0 and result.stdout:
            return result.stdout
    except subprocess.TimeoutExpired, FileNotFoundError, OSError:
        pass

    return os.urandom(len(seed_data) or 200)


async def mutate_async(
    seed_data: bytes, radamsa_path: str = "radamsa", seed_num: int | None = None
) -> bytes:
    """Mutate seed data using radamsa (async, for the fuzzer loop)."""
    cmd: list[str] = [radamsa_path]
    if seed_num is not None:
        cmd.extend(["-s", str(seed_num)])

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(seed_data), timeout=10)
        if proc.returncode == 0 and stdout:
            return stdout
    except TimeoutError, FileNotFoundError, OSError:
        pass

    return os.urandom(len(seed_data) or 200)


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
