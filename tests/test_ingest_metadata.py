"""Metadata pass-through and IngestResult behavior (no Odin binary required)."""

from __future__ import annotations

import json
from pathlib import Path

from aletheia.domain import ArtifactRecord
from aletheia.store.artifacts import IngestPipeline, IngestResult


def _pipeline(tmp_path, scanner):
    return IngestPipeline(
        repo_root=str(tmp_path),
        auto_init=True,
        scanner_factory=lambda binary: scanner,
        identity_available=False,
    )


def _read_record(tmp_path, artifact_id):
    record_path = Path(tmp_path) / "records" / f"{artifact_id}.json"
    return json.loads(record_path.read_text())


def test_ingest_still_returns_str(tmp_path, dummy_scanner, small_file):
    pipeline = _pipeline(tmp_path, dummy_scanner)
    artifact_id = pipeline.ingest(str(small_file), verbose=False)
    assert isinstance(artifact_id, str)
    assert len(artifact_id) == 64


def test_metadata_roundtrips_into_record(tmp_path, dummy_scanner, small_file):
    pipeline = _pipeline(tmp_path, dummy_scanner)
    result = pipeline.ingest_result(
        str(small_file),
        verbose=False,
        source="ocr",
        metadata={"ocr": {"page": 3, "engine": "tesseract"}, "job_id": "j7"},
    )
    meta = _read_record(tmp_path, result.artifact_id)["metadata"]
    assert meta["ingested_from"] == "ocr"
    assert meta["ocr"]["page"] == 3
    assert meta["ocr"]["engine"] == "tesseract"
    assert meta["job_id"] == "j7"
    assert meta["original_filename"] == small_file.name


def test_caller_cannot_override_original_filename(tmp_path, dummy_scanner, small_file):
    pipeline = _pipeline(tmp_path, dummy_scanner)
    result = pipeline.ingest_result(
        str(small_file),
        verbose=False,
        metadata={"original_filename": "EVIL.exe"},
    )
    meta = _read_record(tmp_path, result.artifact_id)["metadata"]
    assert meta["original_filename"] == small_file.name


def test_default_source_is_local(tmp_path, dummy_scanner, small_file):
    pipeline = _pipeline(tmp_path, dummy_scanner)
    result = pipeline.ingest_result(str(small_file), verbose=False)
    meta = _read_record(tmp_path, result.artifact_id)["metadata"]
    assert meta["ingested_from"] == "local"


def test_ingest_result_new_then_duplicate(tmp_path, dummy_scanner, small_file):
    pipeline = _pipeline(tmp_path, dummy_scanner)
    first = pipeline.ingest_result(str(small_file), verbose=False, source="ocr")
    assert isinstance(first, IngestResult)
    assert first.deduplicated is False
    assert first.signed is False
    assert first.created_at_unix_ms > 0

    second = pipeline.ingest_result(str(small_file), verbose=False, source="ocr")
    assert second.deduplicated is True
    assert second.artifact_id == first.artifact_id
    assert second.created_at_unix_ms == first.created_at_unix_ms
    assert second.original_filename == small_file.name


def test_record_version_unchanged_with_metadata(tmp_path, dummy_scanner, small_file):
    pipeline = _pipeline(tmp_path, dummy_scanner)
    result = pipeline.ingest_result(str(small_file), verbose=False, metadata={"ocr": {"page": 1}})
    assert _read_record(tmp_path, result.artifact_id)["record_version"] == "aletheia/ar/1"


def test_domain_arbitrary_nested_metadata_roundtrips():
    raw = {
        "content_object_id": "a" * 64,
        "barcode_object_id": "b" * 64,
        "scan_params": {
            "window_size_bytes": 65536,
            "step_size_bytes": 16384,
            "m_block_size": 1,
            "quant_version": "v0",
            "barcode_len": 16,
        },
        "created_at_unix_ms": 1700000000000,
        "metadata": {
            "original_filename": "x.txt",
            "ingested_from": "ocr",
            "ocr": {"page": 3, "confidence": 0.97},
            "extra": [1, 2, 3],
        },
    }
    out = ArtifactRecord.from_dict(raw).to_dict()
    assert out["metadata"]["ocr"] == {"page": 3, "confidence": 0.97}
    assert out["metadata"]["extra"] == [1, 2, 3]
