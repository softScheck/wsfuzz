import time
from collections import Counter
from pathlib import Path

from wsfuzz.transport import TransportResult


class CrashLogger:
    def __init__(self, log_dir: Path) -> None:
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.crash_count: int = 0
        self.error_types: Counter[str] = Counter()

    def is_interesting(self, result: TransportResult) -> bool:
        if result.error is None:
            return False
        return result.error_type not in ("timeout", "connection_refused")

    def log_crash(
        self,
        iteration: int,
        payload: bytes,
        result: TransportResult,
        seed_index: int,
        radamsa_seed: int,
    ) -> None:
        self.crash_count += 1
        if result.error_type:
            self.error_types[result.error_type] += 1

        ts = int(time.time())
        base = f"crash_{iteration}_{ts}"

        (self.log_dir / f"{base}.bin").write_bytes(payload)
        (self.log_dir / f"{base}.txt").write_text(
            f"iteration: {iteration}\n"
            f"seed_index: {seed_index}\n"
            f"radamsa_seed: {radamsa_seed}\n"
            f"error_type: {result.error_type}\n"
            f"error: {result.error}\n"
            f"duration_ms: {result.duration_ms:.1f}\n"
            f"payload_size: {len(payload)}\n"
            f"response: {result.response!r}\n"
        )

    def summary(self, total_iterations: int) -> str:
        lines = [
            f"\n{'=' * 50}",
            f"iterations: {total_iterations}",
            f"crashes:    {self.crash_count}",
        ]
        if self.error_types:
            lines.append("error types:")
            for etype, count in self.error_types.most_common():
                lines.append(f"  {etype}: {count}")
        lines.append("=" * 50)
        return "\n".join(lines)
