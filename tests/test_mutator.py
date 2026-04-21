import asyncio
from pathlib import Path

from wsfuzz.mutator import load_seeds, mutate, mutate_async


class TestMutate:
    def test_mutate_returns_nonempty_bytes(self):
        result = mutate(b"hello world")
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_mutate_with_seed_is_reproducible(self):
        seed_data = b"test input data"
        result1 = mutate(seed_data, seed_num=42)
        result2 = mutate(seed_data, seed_num=42)
        assert result1 == result2

    def test_mutate_different_seeds_produce_different_output(self):
        seed_data = (
            b"test input data that is long enough for radamsa to mutate differently"
        )
        results = {mutate(seed_data, seed_num=i) for i in range(10)}
        assert len(results) > 1

    def test_mutate_actually_mutates(self):
        """Radamsa should produce output different from the input at least sometimes."""
        seed_data = b"the quick brown fox jumps over the lazy dog"
        results = {mutate(seed_data, seed_num=i) for i in range(20)}
        # At least one mutation should differ from original
        assert seed_data not in results or len(results) > 1

    def test_fallback_returns_random_bytes_of_seed_length(self):
        result = mutate(b"hello", radamsa_path="/nonexistent/radamsa")
        assert len(result) == 5
        # Fallback uses os.urandom — vanishingly unlikely to equal input
        # Run multiple times to verify randomness
        result2 = mutate(b"hello", radamsa_path="/nonexistent/radamsa")
        assert result != result2  # urandom should differ

    def test_fallback_empty_input_uses_default_size(self):
        result = mutate(b"", radamsa_path="/nonexistent/radamsa")
        assert len(result) == 200


class TestMutateAsync:
    def test_async_returns_bytes(self):
        result = asyncio.run(mutate_async(b"hello world"))
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_async_reproducible(self):
        r1 = asyncio.run(mutate_async(b"test data", seed_num=42))
        r2 = asyncio.run(mutate_async(b"test data", seed_num=42))
        assert r1 == r2

    def test_async_matches_sync(self):
        seed = b"test input data"
        sync_result = mutate(seed, seed_num=99)
        async_result = asyncio.run(mutate_async(seed, seed_num=99))
        assert sync_result == async_result

    def test_async_fallback_on_bad_binary(self):
        result = asyncio.run(
            mutate_async(b"hello", radamsa_path="/nonexistent/radamsa")
        )
        assert isinstance(result, bytes)
        assert len(result) == 5

    def test_async_timeout_kills_subprocess(self, monkeypatch):
        class FakeProc:
            def __init__(self):
                self.returncode = None
                self.killed = False
                self.waited = False

            async def communicate(self, _seed_data: bytes):
                return b"", b""

            def kill(self):
                self.killed = True
                self.returncode = -9

            async def wait(self):
                self.waited = True

        proc = FakeProc()

        async def fake_create_subprocess_exec(*args, **kwargs):
            return proc

        async def fake_wait_for(awaitable, timeout):
            await awaitable
            raise TimeoutError

        monkeypatch.setattr(
            "wsfuzz.mutator.asyncio.create_subprocess_exec",
            fake_create_subprocess_exec,
        )
        monkeypatch.setattr("wsfuzz.mutator.asyncio.wait_for", fake_wait_for)

        result = asyncio.run(mutate_async(b"hello"))

        assert isinstance(result, bytes)
        assert len(result) == 5
        assert proc.killed is True
        assert proc.waited is True

    def test_async_timeout_does_not_hang_on_wait_timeout(self, monkeypatch):
        class FakeProc:
            def __init__(self):
                self.returncode = None
                self.killed = False

            async def communicate(self, _seed_data: bytes):
                return b"", b""

            def kill(self):
                self.killed = True

            async def wait(self):
                await asyncio.sleep(10)

        proc = FakeProc()
        calls = 0

        async def fake_create_subprocess_exec(*args, **kwargs):
            return proc

        async def fake_wait_for(awaitable, timeout):
            nonlocal calls
            calls += 1
            if calls == 1:
                await awaitable
            else:
                awaitable.close()
            raise TimeoutError

        monkeypatch.setattr(
            "wsfuzz.mutator.asyncio.create_subprocess_exec",
            fake_create_subprocess_exec,
        )
        monkeypatch.setattr("wsfuzz.mutator.asyncio.wait_for", fake_wait_for)

        result = asyncio.run(mutate_async(b"hello"))

        assert isinstance(result, bytes)
        assert len(result) == 5
        assert proc.killed is True
        assert calls == 2

    def test_async_concurrent_overlaps_work(self, monkeypatch):
        """Concurrent async mutations should overlap subprocess work."""

        active = 0
        max_active = 0

        class FakeProc:
            def __init__(self):
                self.returncode = 0

            async def communicate(self, seed_data: bytes):
                nonlocal active, max_active
                active += 1
                max_active = max(max_active, active)
                try:
                    await asyncio.sleep(0.05)
                    return seed_data + b"-mutated", b""
                finally:
                    active -= 1

        async def fake_create_subprocess_exec(*args, **kwargs):
            return FakeProc()

        monkeypatch.setattr(
            "wsfuzz.mutator.asyncio.create_subprocess_exec",
            fake_create_subprocess_exec,
        )

        async def run_many():
            return await asyncio.gather(
                *[mutate_async(b"seed", seed_num=i) for i in range(10)]
            )

        results = asyncio.run(run_many())

        assert max_active > 1
        assert len(results) == 10
        assert all(result == b"seed-mutated" for result in results)


class TestLoadSeeds:
    def test_load_seeds_from_directory(self, tmp_path):
        (tmp_path / "a.txt").write_bytes(b"seed one")
        (tmp_path / "b.txt").write_bytes(b"seed two")
        seeds = load_seeds(tmp_path)
        assert len(seeds) == 2
        assert b"seed one" in seeds
        assert b"seed two" in seeds

    def test_load_seeds_skips_empty_files(self, tmp_path):
        (tmp_path / "empty.txt").write_bytes(b"")
        (tmp_path / "valid.txt").write_bytes(b"data")
        seeds = load_seeds(tmp_path)
        assert len(seeds) == 1
        assert seeds[0] == b"data"

    def test_load_seeds_missing_dir_returns_random(self):
        seeds = load_seeds(Path("/nonexistent/path"))
        assert len(seeds) == 1
        assert len(seeds[0]) == 200

    def test_load_seeds_empty_dir_returns_random(self, tmp_path):
        seeds = load_seeds(tmp_path)
        assert len(seeds) == 1
        assert len(seeds[0]) == 200

    def test_load_seeds_sorted_deterministically(self, tmp_path):
        (tmp_path / "c.txt").write_bytes(b"third")
        (tmp_path / "a.txt").write_bytes(b"first")
        (tmp_path / "b.txt").write_bytes(b"second")
        seeds = load_seeds(tmp_path)
        assert seeds == [b"first", b"second", b"third"]

    def test_load_seeds_from_project_seeds(self):
        seeds_dir = Path(__file__).parent.parent / "seeds"
        seeds = load_seeds(seeds_dir)
        assert len(seeds) >= 3
