"""
Property / invariant tests — Category 2.

These tests prove that core mathematical and logical properties hold
across a wide range of inputs, independent of any specific expected value.
"""

from __future__ import annotations

import hashlib
import math
import struct
from pathlib import Path

import pytest

from aletheia.ingest import ALBCParser, ArtifactRecordBuilder
from aletheia.utils import compute_file_hash, hash_and_copy_file, hash_bytes

from conftest import build_albc_v1, DummyScanner


# ---------------------------------------------------------------------------
# Hashing invariants
# ---------------------------------------------------------------------------

def test_single_bit_flip_changes_content_hash(tmp_path):
    """Flipping any single bit in a file must change its SHA-256 hash."""
    data = bytearray(b"constant content" * 1000)
    original = tmp_path / "original.bin"
    original.write_bytes(bytes(data))
    h_original, _ = compute_file_hash(original)

    # Flip bit at byte offset 500
    data[500] ^= 0x01
    flipped = tmp_path / "flipped.bin"
    flipped.write_bytes(bytes(data))
    h_flipped, _ = compute_file_hash(flipped)

    assert h_original != h_flipped, "A single bit flip must change the SHA-256 hash"


def test_hash_bytes_matches_compute_file_hash_for_same_content(tmp_path):
    """hash_bytes(data) must equal compute_file_hash(file) when file contains data."""
    data = b"forensic-integrity-check" * 512
    f = tmp_path / "content.bin"
    f.write_bytes(data)

    assert hash_bytes(data) == compute_file_hash(f)[0]


def test_hash_and_copy_produces_same_hash_as_compute_hash(tmp_path):
    """hash_and_copy_file and compute_file_hash must agree on the same content."""
    data = bytes(range(256)) * 512
    src = tmp_path / "src.bin"
    dst = tmp_path / "dst.bin"
    src.write_bytes(data)

    copy_hash, copy_size = hash_and_copy_file(src, dst)
    direct_hash, direct_size = compute_file_hash(src)

    assert copy_hash == direct_hash
    assert copy_size == direct_size


def test_hash_and_copy_destination_matches_source(tmp_path):
    """hash_and_copy_file must produce a byte-identical copy."""
    data = b"original" * 4096
    src = tmp_path / "src.bin"
    dst = tmp_path / "dst.bin"
    src.write_bytes(data)

    hash_and_copy_file(src, dst)

    assert dst.read_bytes() == src.read_bytes()


# ---------------------------------------------------------------------------
# derive_artifact_id invariants
# ---------------------------------------------------------------------------

def test_different_inputs_produce_different_artifact_ids():
    """Different content/barcode pairs must produce different artifact IDs."""
    id_aa = ArtifactRecordBuilder.derive_artifact_id("a" * 64, "b" * 64)
    id_ab = ArtifactRecordBuilder.derive_artifact_id("a" * 64, "c" * 64)
    id_ba = ArtifactRecordBuilder.derive_artifact_id("d" * 64, "b" * 64)

    assert id_aa != id_ab
    assert id_aa != id_ba
    assert id_ab != id_ba


def test_artifact_id_is_64_hex_chars():
    """derive_artifact_id must always return a 64-char lowercase hex string."""
    result = ArtifactRecordBuilder.derive_artifact_id("e" * 64, "f" * 64)
    assert len(result) == 64
    assert all(c in "0123456789abcdef" for c in result)


def test_artifact_id_symmetric_content_vs_barcode_differs():
    """Swapping content_id and barcode_id must produce a different artifact_id."""
    content_id = "a" * 64
    barcode_id = "b" * 64
    normal = ArtifactRecordBuilder.derive_artifact_id(content_id, barcode_id)
    swapped = ArtifactRecordBuilder.derive_artifact_id(barcode_id, content_id)
    assert normal != swapped, "content_id and barcode_id must not be interchangeable"


# ---------------------------------------------------------------------------
# ALBCParser barcode invariants
# ---------------------------------------------------------------------------

def test_compare_barcodes_empty_for_identical_payloads():
    """Identical barcodes must yield no differing regions."""
    payload = bytes(range(50))
    regions = ALBCParser.compare_barcodes(payload, payload, window_size=64, step_size=16)
    assert regions == []


def test_compare_barcodes_nonempty_for_single_byte_difference():
    """A single differing byte must produce at least one region."""
    baseline = bytes(range(20))
    suspect = bytearray(baseline)
    suspect[5] ^= 0xFF
    regions = ALBCParser.compare_barcodes(baseline, bytes(suspect), window_size=64, step_size=16)
    assert len(regions) >= 1


def test_compare_barcodes_region_start_byte_formula():
    """start_byte for region at window i must equal i * step_size."""
    baseline = bytes([0] * 10)
    suspect = bytearray(baseline)
    suspect[3] ^= 0xFF  # Difference only at window 3
    regions = ALBCParser.compare_barcodes(baseline, bytes(suspect), window_size=64, step_size=16)
    assert len(regions) == 1
    _, _, start_byte, _ = regions[0]
    assert start_byte == 3 * 16  # i=3, step=16


def test_compare_barcodes_region_end_byte_formula():
    """end_byte for region at window j must equal j * step_size + window_size."""
    baseline = bytes([0] * 10)
    suspect = bytearray(baseline)
    suspect[7] ^= 0xFF  # Difference only at window 7
    regions = ALBCParser.compare_barcodes(baseline, bytes(suspect), window_size=64, step_size=16)
    assert len(regions) == 1
    _, end_win, _, end_byte = regions[0]
    assert end_byte == end_win * 16 + 64  # j*step + window


def test_compare_barcodes_raw_threshold_filters_small_deltas():
    """Deltas at or below the threshold must not be reported as differences."""
    baseline = [0.0, 0.5, 0.5]
    suspect = [0.0, 0.5 + 0.01, 0.5]  # delta=0.01 < threshold=0.05

    regions = ALBCParser.compare_barcodes_raw(
        baseline, suspect, window_size=64, step_size=16, threshold=0.05
    )
    assert regions == []


def test_compare_barcodes_raw_threshold_reports_large_deltas():
    """Deltas strictly above the threshold must be reported."""
    baseline = [0.0, 0.5, 0.5]
    suspect = [0.0, 0.5 + 0.3, 0.5]  # delta=0.3 > threshold=0.05

    regions = ALBCParser.compare_barcodes_raw(
        baseline, suspect, window_size=64, step_size=16, threshold=0.05
    )
    assert len(regions) == 1


def test_compare_barcodes_raw_empty_for_identical():
    """Identical float arrays must produce no regions."""
    vals = [0.1, 0.5, 0.9, 0.3]
    regions = ALBCParser.compare_barcodes_raw(
        vals, vals[:], window_size=64, step_size=16, threshold=1e-9
    )
    assert regions == []


def test_ingest_same_file_same_artifact_id(tmp_path, monkeypatch):
    """Re-ingesting the same file with the same scanner output must return identical artifact_id."""
    import aletheia.ingest as ingest_module

    scanner = DummyScanner(payload=b"\x10\x20\x30\x40")
    monkeypatch.setattr(ingest_module, "OdinScanner", lambda *a, **kw: scanner)
    monkeypatch.setattr(ingest_module, "IDENTITY_AVAILABLE", False)

    from tests.test_ingest import _DummyRepo
    monkeypatch.setattr(ingest_module, "AletheiaRepository", _DummyRepo)

    source = tmp_path / "source.bin"
    source.write_bytes(b"repeat-me" * 512)

    pipeline = ingest_module.IngestPipeline(repo_root=str(tmp_path))
    id1 = pipeline.ingest(str(source), verbose=False)
    id2 = pipeline.ingest(str(source), verbose=False)

    assert id1 == id2, "Ingesting the same file twice must produce the same artifact_id"
