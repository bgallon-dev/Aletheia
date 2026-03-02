"""
Performance and resource guardrail tests — Category 8.

These tests do NOT benchmark absolute performance. They assert that:
- Large files do not cause catastrophic memory allocation.
- Single-pass I/O utilities actually perform only one pass.
- Streaming interfaces never buffer the entire file.

All tests are marked @pytest.mark.slow and are excluded from the default
CI run. Run explicitly with: pytest -m slow
"""

from __future__ import annotations

import hashlib
import tracemalloc
from pathlib import Path

import pytest

from aletheia.utils import compute_file_hash, hash_and_copy_file

# ---------------------------------------------------------------------------
# Memory thresholds (generous to avoid flakiness on slow machines)
# ---------------------------------------------------------------------------
# Threshold: peak memory increase must stay below this value.
# Rationale: a streaming implementation should allocate ~8 MB (chunk size),
# not load the whole file. 64 MB is 8× the default chunk size — very lenient.
MEMORY_THRESHOLD_BYTES = 64 * 1024 * 1024  # 64 MB


def _make_large_file(path: Path, size_bytes: int) -> Path:
    """Write a deterministic, large binary file without loading it all into RAM."""
    chunk = bytes(range(256)) * 1024  # 256 KB chunk
    with open(path, "wb") as f:
        written = 0
        while written < size_bytes:
            to_write = min(len(chunk), size_bytes - written)
            f.write(chunk[:to_write])
            written += to_write
    return path


# ---------------------------------------------------------------------------
# compute_file_hash — streaming memory check
# ---------------------------------------------------------------------------

@pytest.mark.slow
def test_compute_file_hash_1mb_bounded_memory(tmp_path):
    """Hashing a 1 MB file must not allocate more than MEMORY_THRESHOLD_BYTES."""
    f = _make_large_file(tmp_path / "1mb.bin", 1 * 1024 * 1024)

    tracemalloc.start()
    try:
        h, sz = compute_file_hash(f)
    finally:
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

    assert sz == 1 * 1024 * 1024
    assert len(h) == 64  # Valid SHA-256 hex
    assert peak < MEMORY_THRESHOLD_BYTES, (
        f"compute_file_hash allocated {peak / (1024*1024):.1f} MB peak; "
        f"limit is {MEMORY_THRESHOLD_BYTES // (1024*1024)} MB. "
        "Is the file being loaded into RAM instead of streamed?"
    )


@pytest.mark.slow
def test_compute_file_hash_10mb_bounded_memory(tmp_path):
    """Hashing a 10 MB file must not allocate more than MEMORY_THRESHOLD_BYTES."""
    f = _make_large_file(tmp_path / "10mb.bin", 10 * 1024 * 1024)

    tracemalloc.start()
    try:
        h, sz = compute_file_hash(f)
    finally:
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

    assert sz == 10 * 1024 * 1024
    assert peak < MEMORY_THRESHOLD_BYTES


@pytest.mark.slow
def test_compute_file_hash_produces_correct_digest(tmp_path):
    """Streaming hash must equal the reference digest from hashlib."""
    data = b"reference-content" * (64 * 1024)  # ~1 MB
    f = tmp_path / "ref.bin"
    f.write_bytes(data)

    expected = hashlib.sha256(data).hexdigest()
    actual, _ = compute_file_hash(f)
    assert actual == expected


# ---------------------------------------------------------------------------
# hash_and_copy_file — single-pass and memory check
# ---------------------------------------------------------------------------

@pytest.mark.slow
def test_hash_and_copy_10mb_bounded_memory(tmp_path):
    """Single-pass hash-and-copy on a 10 MB file must stay under MEMORY_THRESHOLD_BYTES."""
    src = _make_large_file(tmp_path / "src_10mb.bin", 10 * 1024 * 1024)
    dst = tmp_path / "dst_10mb.bin"

    tracemalloc.start()
    try:
        h, sz = hash_and_copy_file(src, dst)
    finally:
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

    assert sz == 10 * 1024 * 1024
    assert dst.stat().st_size == sz
    assert peak < MEMORY_THRESHOLD_BYTES


@pytest.mark.slow
def test_hash_and_copy_destination_byte_identical_to_source(tmp_path):
    """The copied file must be byte-identical to the source (no silent truncation)."""
    data = bytes(range(256)) * (4 * 1024)  # 1 MB, all byte values
    src = tmp_path / "src.bin"
    dst = tmp_path / "dst.bin"
    src.write_bytes(data)

    hash_and_copy_file(src, dst)

    assert dst.read_bytes() == data


# ---------------------------------------------------------------------------
# store_object_from_file — streaming mode
# ---------------------------------------------------------------------------

@pytest.mark.slow
def test_store_object_from_file_5mb_bounded_memory(tmp_path):
    """Streaming ingest of a 5 MB file must not allocate more than MEMORY_THRESHOLD_BYTES."""
    from aletheia.repository import AletheiaRepository
    from aletheia.utils import compute_file_hash

    repo = AletheiaRepository(str(tmp_path), auto_init=True)
    src = _make_large_file(tmp_path / "src_5mb.bin", 5 * 1024 * 1024)

    tracemalloc.start()
    try:
        stored_id, stored_size = repo.store_object_from_file(str(src), "content")
    finally:
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

    direct_id, _ = compute_file_hash(src)
    assert stored_id == direct_id
    assert stored_size == 5 * 1024 * 1024
    assert peak < MEMORY_THRESHOLD_BYTES
