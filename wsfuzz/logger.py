import contextlib
import hashlib
import json
import time
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath

from wsfuzz.transport import TransportResult


@dataclass(frozen=True)
class CrashLogResult:
    saved: bool
    fingerprint: str
    duplicate_count: int
    base_name: str | None = None


class CrashLogger:
    def __init__(self, log_dir: Path, *, dedupe: bool = True) -> None:
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.dedupe = dedupe
        self.crash_count: int = 0
        self.duplicate_count: int = 0
        self.error_types: Counter[str] = Counter()
        self._index_path = self.log_dir / "crash_index.json"
        self._fingerprints: dict[str, dict[str, int | str]] = self._load_index()

    def is_interesting(self, result: TransportResult) -> bool:
        if result.error is None:
            return False
        return result.error_type not in (
            "timeout",
            "connection_refused",
            "transport_config",
        )

    def log_crash(
        self,
        iteration: int,
        payload: bytes,
        result: TransportResult,
        seed_index: int,
        radamsa_seed: int,
        extra_metadata: Mapping[str, str] | None = None,
        extra_artifacts: Mapping[str, bytes | str] | None = None,
    ) -> CrashLogResult:
        fingerprint = self._fingerprint(result, extra_metadata)
        if self.dedupe and fingerprint in self._fingerprints:
            entry = self._fingerprints[fingerprint]
            if self._artifact_exists(entry):
                duplicate_count = int(entry["count"]) + 1
                entry["count"] = duplicate_count
                self.duplicate_count += 1
                self._write_index()
                return CrashLogResult(
                    saved=False,
                    fingerprint=fingerprint,
                    duplicate_count=duplicate_count,
                    base_name=str(entry["first"]),
                )
            del self._fingerprints[fingerprint]

        if result.error_type:
            self.error_types[result.error_type] += 1

        base = self._unique_base(iteration)
        self.crash_count += 1

        (self.log_dir / f"{base}.bin").write_bytes(payload)
        metadata = [
            _metadata_line("iteration", iteration),
            _metadata_line("seed_index", seed_index),
            _metadata_line("radamsa_seed", radamsa_seed),
            _metadata_line("error_type", result.error_type),
            _metadata_line("error", result.error),
            _metadata_line("close_code", result.close_code),
            _metadata_line("duration_ms", f"{result.duration_ms:.1f}"),
            _metadata_line("payload_size", len(payload)),
            _metadata_line(
                "response_sha256",
                _sha256(result.response) if result.response is not None else "",
            ),
            _metadata_line("response", repr(result.response)),
        ]
        if extra_metadata:
            metadata.extend(
                _metadata_line(key, value) for key, value in extra_metadata.items()
            )
        (self.log_dir / f"{base}.txt").write_text("\n".join(metadata) + "\n")
        if extra_artifacts:
            for suffix, contents in extra_artifacts.items():
                artifact_path = self.log_dir / f"{base}{suffix}"
                if isinstance(contents, bytes):
                    artifact_path.write_bytes(contents)
                else:
                    artifact_path.write_text(contents)
        entry = self._fingerprints.setdefault(
            fingerprint,
            {
                "count": 0,
                "first": base,
                "error_type": result.error_type or "",
            },
        )
        duplicate_count = int(entry["count"]) + 1
        entry["count"] = duplicate_count
        self._write_index()
        return CrashLogResult(
            saved=True,
            fingerprint=fingerprint,
            duplicate_count=duplicate_count,
            base_name=base,
        )

    def _fingerprint(
        self,
        result: TransportResult,
        extra_metadata: Mapping[str, str] | None,
    ) -> str:
        metadata = extra_metadata or {}
        fingerprint_parts = {
            "transport_mode": metadata.get("transport_mode", ""),
            "message_mode": metadata.get("message_mode", ""),
            "error_type": result.error_type or "",
            "close_code": str(result.close_code or ""),
            "response_sha256": _sha256(result.response)
            if result.response is not None
            else "",
            "scenario_fuzz_ordinal": metadata.get("scenario_fuzz_ordinal", ""),
            "scenario_fuzz_name": metadata.get("scenario_fuzz_name", ""),
            "handshake_fuzz": metadata.get("handshake_fuzz", ""),
            "handshake_version": metadata.get("handshake_version", ""),
            "handshake_extension": metadata.get("handshake_extension", ""),
            "handshake_protocol": metadata.get("handshake_protocol", ""),
        }
        encoded = json.dumps(fingerprint_parts, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode()).hexdigest()

    def _load_index(self) -> dict[str, dict[str, int | str]]:
        if not self._index_path.is_file():
            return {}
        try:
            raw = json.loads(self._index_path.read_text())
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return {}
        if not isinstance(raw, dict):
            return {}
        fingerprints = raw.get("fingerprints")
        if not isinstance(fingerprints, dict):
            return {}
        loaded: dict[str, dict[str, int | str]] = {}
        for fingerprint, entry in fingerprints.items():
            if not isinstance(fingerprint, str) or not isinstance(entry, dict):
                continue
            count = entry.get("count")
            first = entry.get("first")
            error_type = entry.get("error_type", "")
            if (
                isinstance(count, bool)
                or not isinstance(count, int)
                or count < 0
                or not isinstance(first, str)
                or not _is_safe_artifact_base(first)
            ):
                continue
            if not self._base_artifacts_exist(first):
                continue
            loaded[fingerprint] = {
                "count": count,
                "first": first,
                "error_type": str(error_type),
            }
        return loaded

    def _artifact_exists(self, entry: dict[str, int | str]) -> bool:
        first = entry.get("first")
        return isinstance(first, str) and self._base_artifacts_exist(first)

    def _base_artifacts_exist(self, base: str) -> bool:
        return (self.log_dir / f"{base}.bin").is_file() and (
            self.log_dir / f"{base}.txt"
        ).is_file()

    def _write_index(self) -> None:
        contents = (
            json.dumps(
                {"fingerprints": self._fingerprints},
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        tmp_path = self._index_path.with_name(
            f".{self._index_path.name}.{time.time_ns()}.tmp"
        )
        try:
            tmp_path.write_text(contents)
            tmp_path.replace(self._index_path)
        finally:
            with contextlib.suppress(OSError):
                tmp_path.unlink()

    def _unique_base(self, iteration: int) -> str:
        base = f"crash_{iteration}_{time.time_ns()}"
        if not (self.log_dir / f"{base}.bin").exists():
            return base
        suffix = 1
        while (self.log_dir / f"{base}_{suffix}.bin").exists():
            suffix += 1
        return f"{base}_{suffix}"

    def summary(self, total_iterations: int) -> str:
        lines = [
            f"\n{'=' * 50}",
            f"iterations: {total_iterations}",
            f"crashes:    {self.crash_count}",
        ]
        if self.dedupe:
            lines.append(f"duplicates: {self.duplicate_count}")
        if self.error_types:
            lines.append("error types:")
            for etype, count in self.error_types.most_common():
                lines.append(f"  {etype}: {count}")
        lines.append("=" * 50)
        return "\n".join(lines)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _metadata_line(key: str, value: object) -> str:
    return f"{key}: {_metadata_value(value)}"


def _metadata_value(value: object) -> str:
    return str(value).replace("\r", "\\r").replace("\n", "\\n")


def _is_safe_artifact_base(base: str) -> bool:
    return (
        bool(base)
        and PurePosixPath(base).name == base
        and PureWindowsPath(base).name == base
    )
