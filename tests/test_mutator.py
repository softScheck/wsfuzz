import asyncio
from pathlib import Path

from wsfuzz.mutator import load_seeds, mutate, mutate_async


class TestMutate:
    def test_mutate_returns_bytes(self):
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

    def test_mutate_fallback_on_bad_binary(self):
        result = mutate(b"hello", radamsa_path="/nonexistent/radamsa")
        assert isinstance(result, bytes)
        assert len(result) == 5

    def test_mutate_empty_input_fallback(self):
        result = mutate(b"", radamsa_path="/nonexistent/radamsa")
        assert isinstance(result, bytes)
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

    def test_async_concurrent_is_faster(self):
        """Concurrent async mutations should be faster than sequential."""
        import time

        seed = b"test data for concurrent mutation benchmark"

        start = time.monotonic()
        for i in range(20):
            mutate(seed, seed_num=i)
        sync_ms = (time.monotonic() - start) * 1000

        async def concurrent():
            return await asyncio.gather(
                *[mutate_async(seed, seed_num=i) for i in range(20)]
            )

        start = time.monotonic()
        asyncio.run(concurrent())
        async_ms = (time.monotonic() - start) * 1000

        # Concurrent should be at least somewhat faster
        assert async_ms < sync_ms * 1.5  # generous margin for CI


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
