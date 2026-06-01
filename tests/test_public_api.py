"""Stable public API surface for embedding Aletheia in other pipelines."""

from __future__ import annotations

import json
import struct
import tempfile


def test_public_imports():
    from aletheia import (  # noqa: F401
        AletheiaRepository,
        ArtifactRecord,
        ArtifactVerifier,
        IngestPipeline,
        IngestResult,
        __version__,
        ingest_file,
    )

    assert __version__
    assert callable(ingest_file)


def _albc_v1(payload: bytes = b"\x01\x02\x03\x04") -> bytes:
    header = b"ALBC0001"
    header += struct.pack("<I", 64)
    header += struct.pack("<I", 16)
    header += struct.pack("<I", 1)
    header += struct.pack("<I", 0)
    header += struct.pack("<Q", len(payload))
    return header + payload


class _DummyScanner:
    def scan(self, file_path: str, **kwargs):
        albc = _albc_v1()
        tmp = tempfile.NamedTemporaryFile(suffix=".albc", delete=False)
        tmp.write(albc)
        tmp.close()
        return albc, tmp.name


def test_ingest_file_returns_result_with_ocr_provenance(tmp_path, monkeypatch):
    monkeypatch.setattr("aletheia.ingest.OdinScanner", lambda *a, **k: _DummyScanner())
    from aletheia import IngestResult, ingest_file

    f = tmp_path / "doc.txt"
    f.write_text("ocr output")
    repo = tmp_path / "repo"

    result = ingest_file(str(f), repo=str(repo), metadata={"ocr": {"page": 2}})
    assert isinstance(result, IngestResult)
    assert result.deduplicated is False

    record = json.loads((repo / "records" / f"{result.artifact_id}.json").read_text())
    assert record["metadata"]["ingested_from"] == "ocr"  # ingest_file defaults source="ocr"
    assert record["metadata"]["ocr"]["page"] == 2

    # Idempotent: identical content re-ingests as a duplicate.
    again = ingest_file(str(f), repo=str(repo), metadata={"ocr": {"page": 2}})
    assert again.deduplicated is True
    assert again.artifact_id == result.artifact_id
