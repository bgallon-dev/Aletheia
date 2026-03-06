"""
CAS (Content-Addressed Storage) correctness and atomicity tests — Category 5.

Prove that ingestion does not corrupt repository state and handles partial
failure gracefully. The source of truth is always the filesystem
(objects/ + records/), never the SQLite index.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from aletheia.store.repository import AletheiaRepository, ObjectNotFoundError, RepositoryError

from conftest import minimal_record


# ---------------------------------------------------------------------------
# store_object: content-addressing correctness
# ---------------------------------------------------------------------------

def test_store_object_returns_sha256_hex(initialized_repo):
    data = b"aletheia-content-addressed"
    object_id = initialized_repo.store_object(data, "content")
    expected = hashlib.sha256(data).hexdigest()
    assert object_id == expected


def test_store_object_same_content_returns_same_id(initialized_repo):
    data = b"duplicate-me"
    id1 = initialized_repo.store_object(data, "content")
    id2 = initialized_repo.store_object(data, "content")
    assert id1 == id2


def test_store_object_same_content_no_duplicate_files(initialized_repo):
    """Storing identical content twice must leave exactly one file on disk."""
    data = b"unique-object"
    object_id = initialized_repo.store_object(data, "content")
    initialized_repo.store_object(data, "content")  # Second store

    prefix = object_id[:initialized_repo.object_fanout]
    files = list((initialized_repo.objects_dir / prefix).iterdir())
    matching = [f for f in files if f.name == object_id]
    assert len(matching) == 1, f"Expected 1 object file, found {len(matching)}"


def test_store_object_different_content_different_id(initialized_repo):
    id1 = initialized_repo.store_object(b"content-A", "content")
    id2 = initialized_repo.store_object(b"content-B", "content")
    assert id1 != id2


def test_store_object_from_file_matches_direct_hash(initialized_repo, tmp_path):
    """store_object_from_file must return the same hash as compute_file_hash."""
    from aletheia.utils import compute_file_hash

    data = b"file-content" * 1024
    src = tmp_path / "source.bin"
    src.write_bytes(data)

    stored_id, stored_size = initialized_repo.store_object_from_file(str(src), "content")
    direct_id, direct_size = compute_file_hash(src)

    assert stored_id == direct_id
    assert stored_size == direct_size


# ---------------------------------------------------------------------------
# get_object_bytes: round-trip retrieval
# ---------------------------------------------------------------------------

def test_get_object_bytes_round_trip(initialized_repo):
    """Store bytes then retrieve them — must be byte-identical."""
    data = b"round-trip-check" * 100
    object_id = initialized_repo.store_object(data, "barcode")
    retrieved = initialized_repo.get_object_bytes(object_id, obj_type_hint="barcode")
    assert retrieved == data


def test_get_object_bytes_raises_for_unknown_id(initialized_repo):
    with pytest.raises(ObjectNotFoundError):
        initialized_repo.get_object_bytes("0" * 64)


# ---------------------------------------------------------------------------
# artifact_exists
# ---------------------------------------------------------------------------

def test_artifact_exists_false_initially(initialized_repo):
    assert initialized_repo.artifact_exists("a" * 64) is False


def test_artifact_exists_true_after_store_artifact(initialized_repo):
    content_id = initialized_repo.store_object(b"content", "content")
    barcode_id = initialized_repo.store_object(b"barcode", "barcode")

    artifact_id = "e" * 64
    record = minimal_record(
        content_object_id=content_id,
        barcode_object_id=barcode_id,
    )
    initialized_repo.store_artifact(artifact_id, record)
    assert initialized_repo.artifact_exists(artifact_id) is True


# ---------------------------------------------------------------------------
# audit_objects: integrity verification
# ---------------------------------------------------------------------------

def test_audit_objects_clean_repo_has_no_corrupted(initialized_repo):
    """A freshly written object should pass the audit without corruption."""
    initialized_repo.store_object(b"clean-object", "content")
    stats = initialized_repo.audit_objects(verbose=False)
    assert stats["corrupted"] == []
    assert stats["missing_files"] == []


def test_audit_objects_detects_corrupted_object(initialized_repo):
    """Manually overwriting stored bytes must trigger a 'Content hash mismatch'."""
    data = b"original-bytes" * 50
    object_id = initialized_repo.store_object(data, "content")

    # Locate the stored file and corrupt its contents
    obj_path = initialized_repo.get_object_path(object_id)
    assert obj_path is not None
    obj_path.write_bytes(b"corrupted!" * 70)  # Same size won't trigger size check; different hash will

    stats = initialized_repo.audit_objects(verbose=False)
    corrupted_ids = [c["object_id"] for c in stats["corrupted"]]
    assert object_id in corrupted_ids, (
        f"audit_objects did not detect the corrupted object {object_id[:16]}…"
    )


def test_audit_objects_detects_missing_file(initialized_repo):
    """Deleting a stored file after indexing must appear as 'missing_files'."""
    data = b"soon-to-be-gone"
    object_id = initialized_repo.store_object(data, "content")

    obj_path = initialized_repo.get_object_path(object_id)
    assert obj_path is not None
    obj_path.unlink()

    stats = initialized_repo.audit_objects(verbose=False)
    assert object_id in stats["missing_files"]


# ---------------------------------------------------------------------------
# Atomicity: tmp file cleanup
# ---------------------------------------------------------------------------

def test_tmp_dir_is_empty_after_successful_store(initialized_repo, tmp_path):
    """store_object must not leave any files in tmp/ after a successful write."""
    data = b"transient" * 100
    initialized_repo.store_object(data, "content")

    tmp_files = list(initialized_repo.tmp_dir.iterdir())
    assert tmp_files == [], f"tmp/ should be empty after store, found: {tmp_files}"


def test_store_object_from_file_cleans_tmp_on_success(initialized_repo, tmp_path):
    """store_object_from_file must leave tmp/ empty after a clean ingest."""
    src = tmp_path / "src.bin"
    src.write_bytes(b"stream-me" * 1024)

    initialized_repo.store_object_from_file(str(src), "content")

    tmp_files = list(initialized_repo.tmp_dir.iterdir())
    assert tmp_files == [], f"tmp/ should be empty, found: {tmp_files}"


# ---------------------------------------------------------------------------
# Ingest idempotency
# ---------------------------------------------------------------------------

def test_ingest_idempotent_returns_same_artifact_id(tmp_path, monkeypatch):
    """Ingesting the same file twice with the same scanner output = same artifact_id."""
    import aletheia.ingest as ingest_module
    from tests.test_ingest import _DummyRepo
    from conftest import DummyScanner

    scanner = DummyScanner(payload=b"\xAA\xBB\xCC\xDD")
    monkeypatch.setattr(ingest_module, "OdinScanner", lambda *a, **kw: scanner)
    monkeypatch.setattr(ingest_module, "AletheiaRepository", _DummyRepo)
    monkeypatch.setattr(ingest_module, "IDENTITY_AVAILABLE", False)

    source = tmp_path / "source.bin"
    source.write_bytes(b"idempotent-content" * 256)

    pipeline = ingest_module.IngestPipeline(repo_root=str(tmp_path))
    id1 = pipeline.ingest(str(source), verbose=False)
    id2 = pipeline.ingest(str(source), verbose=False)

    assert id1 == id2
