"""
Golden tests — Category 1: Determinism and regression protection.

These tests verify that specific inputs always produce specific outputs,
and that the JSON schema structure does not silently drift. The golden
values in tests/fixtures/goldens/ must be updated intentionally and reviewed
in code review.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from aletheia.domain import ArtifactRecord, ScanParams
from aletheia.ingest import ALBCParser, ArtifactRecordBuilder
from aletheia.utils import compute_file_hash, hash_bytes

from conftest import GOLDENS_DIR, build_albc_v1


# ---------------------------------------------------------------------------
# derive_artifact_id  (Category 1a — deterministic ID derivation)
# ---------------------------------------------------------------------------

def test_derive_artifact_id_matches_golden():
    """Output must exactly equal the committed golden value.

    If this test fails after a code change, you likely changed the hashing
    prefix or the byte-encoding of content/barcode IDs. Bump the version and
    regenerate the golden file.
    """
    golden = json.loads((GOLDENS_DIR / "derive_artifact_id.json").read_text())
    content_id = golden["inputs"]["content_object_id"]
    barcode_id = golden["inputs"]["barcode_object_id"]
    expected = golden["expected_artifact_id"]

    actual = ArtifactRecordBuilder.derive_artifact_id(content_id, barcode_id)
    assert actual == expected, (
        f"derive_artifact_id output changed. Expected golden:\n  {expected}\nGot:\n  {actual}\n"
        "Update tests/fixtures/goldens/derive_artifact_id.json only when intentionally "
        "changing the ID derivation algorithm."
    )


def test_derive_artifact_id_is_idempotent():
    """Calling derive_artifact_id with the same inputs three times must be identical."""
    content_id = "c" * 64
    barcode_id = "d" * 64

    results = [
        ArtifactRecordBuilder.derive_artifact_id(content_id, barcode_id)
        for _ in range(3)
    ]
    assert len(set(results)) == 1, "derive_artifact_id is not idempotent"


def test_derive_artifact_id_implements_documented_formula():
    """The ID is SHA-256(prefix || content_bytes || barcode_bytes) per the docstring."""
    content_id = "a" * 64
    barcode_id = "b" * 64

    prefix = b"ALETHEIA_AR_V1"
    expected = hashlib.sha256(
        prefix + bytes.fromhex(content_id) + bytes.fromhex(barcode_id)
    ).hexdigest()

    actual = ArtifactRecordBuilder.derive_artifact_id(content_id, barcode_id)
    assert actual == expected


# ---------------------------------------------------------------------------
# ArtifactRecord key-set stability  (Category 1b — schema regression)
# ---------------------------------------------------------------------------

def test_artifact_record_to_dict_required_keys_stable():
    """to_dict() must emit exactly the documented required keys (no silent additions/removals)."""
    golden = json.loads((GOLDENS_DIR / "artifact_record_v1.json").read_text())
    required = set(golden["required_keys"])

    record = ArtifactRecord(
        record_version="aletheia/ar/1",
        content_object_id="a" * 64,
        barcode_object_id="b" * 64,
        scan_params=ScanParams(
            window_size_bytes=65536,
            step_size_bytes=16384,
            m_block_size=1,
            quant_version="v0",
            barcode_len=16,
        ),
        created_at_unix_ms=1700000000000,
        metadata={},
    )
    d = record.to_dict()
    assert required.issubset(d.keys()), (
        f"Missing keys in to_dict(): {required - d.keys()}"
    )


def test_scan_params_to_dict_key_set_stable():
    """ScanParams.to_dict() must emit exactly the documented keys."""
    golden = json.loads((GOLDENS_DIR / "artifact_record_v1.json").read_text())
    expected_keys = set(golden["scan_params_keys"])

    sp = ScanParams(
        window_size_bytes=65536,
        step_size_bytes=16384,
        m_block_size=1,
        quant_version="v0",
        barcode_len=16,
    )
    actual_keys = set(sp.to_dict().keys())
    assert actual_keys == expected_keys, (
        f"ScanParams.to_dict() key-set changed.\n"
        f"  Added:   {actual_keys - expected_keys}\n"
        f"  Removed: {expected_keys - actual_keys}"
    )


def test_artifact_record_round_trip_is_lossless():
    """from_dict(to_dict(record)) must equal the original dict."""
    record = ArtifactRecord(
        record_version="aletheia/ar/1",
        content_object_id="a" * 64,
        barcode_object_id="b" * 64,
        scan_params=ScanParams(
            window_size_bytes=65536,
            step_size_bytes=16384,
            m_block_size=1,
            quant_version="v0",
            barcode_len=16,
        ),
        created_at_unix_ms=1700000000000,
        metadata={"original_filename": "test.bin"},
    )
    first_dict = record.to_dict()
    second_dict = ArtifactRecord.from_dict(first_dict).to_dict()
    assert first_dict == second_dict, "Round-trip serialization is lossy"


# ---------------------------------------------------------------------------
# compare_barcodes golden output  (Category 1c — localization regression)
# ---------------------------------------------------------------------------

def test_compare_barcodes_golden_output():
    """compare_barcodes with the canonical test case must match the committed golden."""
    golden = json.loads((GOLDENS_DIR / "compare_barcodes_output.json").read_text())
    inputs = golden["inputs"]
    expected = [tuple(r) for r in golden["expected_regions"]]

    baseline = bytes(inputs["baseline"])
    suspect = bytes(inputs["suspect"])

    actual = ALBCParser.compare_barcodes(
        baseline,
        suspect,
        window_size=inputs["window_size"],
        step_size=inputs["step_size"],
    )
    assert actual == expected, (
        f"compare_barcodes output changed.\n"
        f"  Expected: {expected}\n  Got:      {actual}"
    )


# ---------------------------------------------------------------------------
# Hashing determinism  (Category 1d — utility regression)
# ---------------------------------------------------------------------------

def test_hash_bytes_known_value():
    """hash_bytes(b'test') must match the well-known SHA-256 digest."""
    expected = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    assert hash_bytes(b"test") == expected


def test_compute_file_hash_deterministic(deterministic_file):
    """Hashing the same seeded file twice must produce identical results."""
    h1, sz1 = compute_file_hash(deterministic_file)
    h2, sz2 = compute_file_hash(deterministic_file)
    assert h1 == h2
    assert sz1 == sz2


def test_compute_file_hash_empty_file(tmp_path):
    """SHA-256 of empty file is the well-known empty-hash value."""
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    h, sz = compute_file_hash(empty)
    assert h == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert sz == 0
